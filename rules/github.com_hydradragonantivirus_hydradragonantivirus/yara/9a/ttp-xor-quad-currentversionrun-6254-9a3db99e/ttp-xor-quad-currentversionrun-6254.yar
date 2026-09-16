rule TTP_XOR_QUAD_CurrentVersionRun_6254 {
  strings:
    $key_6254 = { 31 3b [2] 15 35 [2] 3e 19 [2] 10 3b [2] 04 20 [2] 0b 3a [2] 15 27 [2] 17 26 [2] 0c 20 [2] 10 27 [2] 0c 08 }

  condition:
    any of them
}