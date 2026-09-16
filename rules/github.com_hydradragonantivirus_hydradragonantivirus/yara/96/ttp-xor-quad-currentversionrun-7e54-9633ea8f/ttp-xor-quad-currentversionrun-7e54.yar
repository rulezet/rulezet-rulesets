rule TTP_XOR_QUAD_CurrentVersionRun_7e54 {
  strings:
    $key_7e54 = { 2d 3b [2] 09 35 [2] 22 19 [2] 0c 3b [2] 18 20 [2] 17 3a [2] 09 27 [2] 0b 26 [2] 10 20 [2] 0c 27 [2] 10 08 }

  condition:
    any of them
}