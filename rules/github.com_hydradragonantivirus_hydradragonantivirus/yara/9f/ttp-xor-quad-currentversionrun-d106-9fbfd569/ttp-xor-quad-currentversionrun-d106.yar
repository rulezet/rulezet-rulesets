rule TTP_XOR_QUAD_CurrentVersionRun_d106 {
  strings:
    $key_d106 = { 82 69 [2] a6 67 [2] 8d 4b [2] a3 69 [2] b7 72 [2] b8 68 [2] a6 75 [2] a4 74 [2] bf 72 [2] a3 75 [2] bf 5a }

  condition:
    any of them
}