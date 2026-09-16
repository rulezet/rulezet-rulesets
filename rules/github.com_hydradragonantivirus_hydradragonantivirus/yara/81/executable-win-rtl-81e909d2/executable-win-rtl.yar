rule executable_win_rtl {
  meta:
    is_exe    = true
    type      = "win-rtl"
    rank      = 10
    revision  = "100"
    date      = "July 29 2015"
    desc      = "Right to Left compression LZNT1"
    author    = "@tylabs"
    copyright = "QuickSand.io 2015"
    tlp       = "green"

  strings:
    $s1 = { 20 70 72 6F 67 72 61 6D 00 20 63 61 6E 6E 6F 74 20 00 62 65 20 72 75 6E 20 69 00 6E 20 44 4F 53 20 6D 6F }  
  condition:
    1 of them
}