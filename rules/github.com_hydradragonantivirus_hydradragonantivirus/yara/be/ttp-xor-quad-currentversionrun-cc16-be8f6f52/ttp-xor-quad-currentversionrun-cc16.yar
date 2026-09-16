rule TTP_XOR_QUAD_CurrentVersionRun_cc16 {
  strings:
    $key_cc16 = { 9f 79 [2] bb 77 [2] 90 5b [2] be 79 [2] aa 62 [2] a5 78 [2] bb 65 [2] b9 64 [2] a2 62 [2] be 65 [2] a2 4a }

  condition:
    any of them
}