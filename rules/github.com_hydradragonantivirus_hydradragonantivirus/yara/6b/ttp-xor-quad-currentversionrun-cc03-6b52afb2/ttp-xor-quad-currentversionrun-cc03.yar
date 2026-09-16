rule TTP_XOR_QUAD_CurrentVersionRun_cc03 {
  strings:
    $key_cc03 = { 9f 6c [2] bb 62 [2] 90 4e [2] be 6c [2] aa 77 [2] a5 6d [2] bb 70 [2] b9 71 [2] a2 77 [2] be 70 [2] a2 5f }

  condition:
    any of them
}