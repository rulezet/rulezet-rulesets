rule TTP_XOR_QUAD_CurrentVersionRun_dfed {
  strings:
    $key_dfed = { 8c 82 [2] a8 8c [2] 83 a0 [2] ad 82 [2] b9 99 [2] b6 83 [2] a8 9e [2] aa 9f [2] b1 99 [2] ad 9e [2] b1 b1 }

  condition:
    any of them
}