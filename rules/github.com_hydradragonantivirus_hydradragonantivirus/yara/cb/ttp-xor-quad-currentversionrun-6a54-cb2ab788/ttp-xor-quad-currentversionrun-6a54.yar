rule TTP_XOR_QUAD_CurrentVersionRun_6a54 {
  strings:
    $key_6a54 = { 39 3b [2] 1d 35 [2] 36 19 [2] 18 3b [2] 0c 20 [2] 03 3a [2] 1d 27 [2] 1f 26 [2] 04 20 [2] 18 27 [2] 04 08 }

  condition:
    any of them
}