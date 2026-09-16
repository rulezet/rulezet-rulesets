rule TTP_XOR_QUAD_CurrentVersionRun_c7e0 {
  strings:
    $key_c7e0 = { 94 8f [2] b0 81 [2] 9b ad [2] b5 8f [2] a1 94 [2] ae 8e [2] b0 93 [2] b2 92 [2] a9 94 [2] b5 93 [2] a9 bc }

  condition:
    any of them
}