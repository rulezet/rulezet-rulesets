rule TTP_XOR_QUAD_CurrentVersionRun_e507 {
  strings:
    $key_e507 = { b6 68 [2] 92 66 [2] b9 4a [2] 97 68 [2] 83 73 [2] 8c 69 [2] 92 74 [2] 90 75 [2] 8b 73 [2] 97 74 [2] 8b 5b }

  condition:
    any of them
}