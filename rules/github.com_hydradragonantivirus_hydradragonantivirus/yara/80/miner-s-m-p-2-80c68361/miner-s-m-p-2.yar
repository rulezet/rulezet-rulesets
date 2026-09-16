rule miner_s_m_p_2 {
  meta:
    description = "miner-exe - from files s, m, p"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
    hash2       = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
    hash3       = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"

  strings:
    $x1  = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
    $s2  = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
    $s3  = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
    $s4  = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s5  = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
    $s6  = "User-Agent: cpuminer/2.3.3" fullword ascii
    $s7  = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
    $s8  = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
    $s9  = "getwork failed, retry after %d seconds" fullword ascii
    $s10 = "Failed to call rpc command after %i tries" fullword ascii
    $s11 = "Failed to get Stratum session id" fullword ascii
    $s12 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
    $s13 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
    $s14 = "-S, --syslog          use system log for output messages" fullword ascii
    $s15 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
    $s16 = "%s: unsupported non-option argument '%s'" fullword ascii
    $s17 = "-p, --pass=PASSWORD   password for mining server" fullword ascii
    $s18 = "client.get_version" fullword ascii
    $s19 = "Tried to call rpc2 command before authentication" fullword ascii
    $s20 = "-s, --scantime=N      upper bound on time spent scanning current work when" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 9000KB and (1 of ($x*) and 4 of them)
    ) or (all of them)
}