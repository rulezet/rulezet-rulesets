rule TTP_XOR_QUAD_CurrentVersionRun_d7e0 {
  strings:
    $key_d7e0 = { 84 8f [2] a0 81 [2] 8b ad [2] a5 8f [2] b1 94 [2] be 8e [2] a0 93 [2] a2 92 [2] b9 94 [2] a5 93 [2] b9 bc }

  condition:
    any of them
}