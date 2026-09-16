rule TTP_XOR_QUAD_CurrentVersionRun_756b {
  strings:
    $key_756b = { 26 04 [2] 02 0a [2] 29 26 [2] 07 04 [2] 13 1f [2] 1c 05 [2] 02 18 [2] 00 19 [2] 1b 1f [2] 07 18 [2] 1b 37 }

  condition:
    any of them
}