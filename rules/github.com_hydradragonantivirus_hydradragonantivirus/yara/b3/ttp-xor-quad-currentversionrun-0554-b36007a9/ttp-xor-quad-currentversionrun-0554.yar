rule TTP_XOR_QUAD_CurrentVersionRun_0554 {
  strings:
    $key_0554 = { 56 3b [2] 72 35 [2] 59 19 [2] 77 3b [2] 63 20 [2] 6c 3a [2] 72 27 [2] 70 26 [2] 6b 20 [2] 77 27 [2] 6b 08 }

  condition:
    any of them
}