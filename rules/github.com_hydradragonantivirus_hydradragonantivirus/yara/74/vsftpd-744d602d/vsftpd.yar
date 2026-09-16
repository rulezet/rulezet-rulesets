rule vsftpd {
  meta:
    description   = "Detection patterns for the tool 'vsftpd' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "vsftpd"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1  = /Bad\sHTTP\sverb\./ nocase ascii wide
            $string2  = /bug:\spid\sactive\sin\sptrace_sandbox_free/ nocase ascii wide
            $string3  = /Connection\srefused:\stcp_wrappers\sdenial\./ nocase ascii wide
            $string4  = /Connection\srefused:\stoo\smany\ssessions\sfor\sthis\saddress\./ nocase ascii wide
            $string5  = /Could\snot\sset\sfile\smodification\stime\./ nocase ascii wide
            $string6  = /couldn\'t\shandle\ssandbox\sevent/ nocase ascii wide
            $string7  = /Input\sline\stoo\slong\./ nocase ascii wide
            $string8  = /pasv\sand\sport\sboth\sactive/ nocase ascii wide
            $string9  = /poor\sbuffer\saccounting\sin\sstr_netfd_alloc/ nocase ascii wide
            $string10 = /port\sand\spasv\sboth\sactive/ nocase ascii wide
            $string11 = /PTRACE_SETOPTIONS\sfailure/ nocase ascii wide
            $string12 = /syscall\s.*\sout\sof\sbounds/ nocase ascii wide
            $string13 = /syscall\snot\spermitted:/ nocase ascii wide
            $string14 = /syscall\svalidate\sfailed:/ nocase ascii wide
            $string15 = /Transfer\sdone\s\(but\sfailed\sto\sopen\sdirectory\)\./ nocase ascii wide
            $string16 = /vsf_sysutil_read_loop/ nocase ascii wide
            $string17 = /weird\sstatus:/ nocase ascii wide

  condition:
    any of them
}