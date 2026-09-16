rule TTP_XOR_QUAD_CurrentVersionRun_c316 {
  strings:
    $key_c316 = { 90 79 [2] b4 77 [2] 9f 5b [2] b1 79 [2] a5 62 [2] aa 78 [2] b4 65 [2] b6 64 [2] ad 62 [2] b1 65 [2] ad 4a }

  condition:
    any of them
}