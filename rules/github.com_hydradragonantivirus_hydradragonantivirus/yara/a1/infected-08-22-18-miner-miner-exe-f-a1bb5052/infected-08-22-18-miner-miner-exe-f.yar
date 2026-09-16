rule infected_08_22_18_miner_miner_exe_f {
  meta:
    description = "miner-exe - file f"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "45ed59d5b27d22567d91a65623d3b7f11726f55b497c383bc2d8d330e5e17161"

  strings:
    $s1  = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" fullword ascii
    $s2  = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" fullword ascii
    $s3  = "Fake name process" fullword ascii
    $s4  = "Couldn't execute" fullword ascii
    $s5  = "==> Fakename: %s PidNum: %d" fullword ascii
    $s6  = "execv@@GLIBC_2.0" fullword ascii
    $s7  = "Error: /dev/null" fullword ascii
    $s8  = "getpwnam" fullword ascii
    $s9  = "<command line>" fullword ascii
    $s10 = "getgrnam" fullword ascii
    $s11 = "Change UID/GID, use another user (optional)" fullword ascii
    $s12 = "/usr/src/packages/BUILD/glibc-2.3/cc/config.h" fullword ascii
    $s13 = "__i686.get_pc_thunk.bx" fullword ascii
    $s14 = ".gnu.version" fullword ascii
    $s15 = ".gnu.version_r" fullword ascii
    $s16 = "getenv@@GLIBC_2.0" fullword ascii
    $s17 = "getpid@@GLIBC_2.0" fullword ascii
    $s18 = "getcwd@@GLIBC_2.0" fullword ascii
    $s19 = "getgrnam@@GLIBC_2.0" fullword ascii
    $s20 = "getpwnam@@GLIBC_2.0" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}