rule TTP_XOR_QUAD_CurrentVersionRun_3807 {
  strings:
    $key_3807 = { 6b 68 [2] 4f 66 [2] 64 4a [2] 4a 68 [2] 5e 73 [2] 51 69 [2] 4f 74 [2] 4d 75 [2] 56 73 [2] 4a 74 [2] 56 5b }

  condition:
    any of them
}