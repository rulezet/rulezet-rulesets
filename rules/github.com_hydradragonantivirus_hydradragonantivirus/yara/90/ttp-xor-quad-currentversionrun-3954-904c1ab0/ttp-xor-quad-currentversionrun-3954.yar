rule TTP_XOR_QUAD_CurrentVersionRun_3954 {
  strings:
    $key_3954 = { 6a 3b [2] 4e 35 [2] 65 19 [2] 4b 3b [2] 5f 20 [2] 50 3a [2] 4e 27 [2] 4c 26 [2] 57 20 [2] 4b 27 [2] 57 08 }

  condition:
    any of them
}