rule TTP_XOR_QUAD_CurrentVersionRun_6d54 {
  strings:
    $key_6d54 = { 3e 3b [2] 1a 35 [2] 31 19 [2] 1f 3b [2] 0b 20 [2] 04 3a [2] 1a 27 [2] 18 26 [2] 03 20 [2] 1f 27 [2] 03 08 }

  condition:
    any of them
}