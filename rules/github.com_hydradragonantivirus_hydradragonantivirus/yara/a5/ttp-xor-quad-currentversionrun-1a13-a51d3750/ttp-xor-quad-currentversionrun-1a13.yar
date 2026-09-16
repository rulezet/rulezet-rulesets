rule TTP_XOR_QUAD_CurrentVersionRun_1a13 {
  strings:
    $key_1a13 = { 49 7c [2] 6d 72 [2] 46 5e [2] 68 7c [2] 7c 67 [2] 73 7d [2] 6d 60 [2] 6f 61 [2] 74 67 [2] 68 60 [2] 74 4f }

  condition:
    any of them
}