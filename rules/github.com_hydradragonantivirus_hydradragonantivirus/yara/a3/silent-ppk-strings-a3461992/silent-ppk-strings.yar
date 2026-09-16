rule silent_ppk_strings {
  meta:
    author = "Geoff Alexander <geoff@citizenlab.ca>"

  strings:
    $s1 = "MainCommandJobSub"
    $s2 = "MainFun002"
    $s3 = "mRecvPkgFun"
    $s4 = "while -- ClientConnect"
    $s5 = "svsdll.log"
    $s6 = "ppk.dat"

  condition:
    uint16(0) == 0x5a4d and 4 of ($s*)
}