rule TTP_XOR_QUAD_CurrentVersionRun_c706 {
  strings:
    $key_c706 = { 94 69 [2] b0 67 [2] 9b 4b [2] b5 69 [2] a1 72 [2] ae 68 [2] b0 75 [2] b2 74 [2] a9 72 [2] b5 75 [2] a9 5a }

  condition:
    any of them
}