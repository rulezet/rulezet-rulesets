rule TTP_XOR_QUAD_CurrentVersionRun_d616 {
  strings:
    $key_d616 = { 85 79 [2] a1 77 [2] 8a 5b [2] a4 79 [2] b0 62 [2] bf 78 [2] a1 65 [2] a3 64 [2] b8 62 [2] a4 65 [2] b8 4a }

  condition:
    any of them
}