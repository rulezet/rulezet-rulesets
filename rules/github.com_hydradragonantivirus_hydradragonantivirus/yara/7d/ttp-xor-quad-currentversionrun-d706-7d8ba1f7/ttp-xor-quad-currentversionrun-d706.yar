rule TTP_XOR_QUAD_CurrentVersionRun_d706 {
  strings:
    $key_d706 = { 84 69 [2] a0 67 [2] 8b 4b [2] a5 69 [2] b1 72 [2] be 68 [2] a0 75 [2] a2 74 [2] b9 72 [2] a5 75 [2] b9 5a }

  condition:
    any of them
}