rule TTP_XOR_QUAD_CurrentVersionRun_b6e0 {
  strings:
    $key_b6e0 = { e5 8f [2] c1 81 [2] ea ad [2] c4 8f [2] d0 94 [2] df 8e [2] c1 93 [2] c3 92 [2] d8 94 [2] c4 93 [2] d8 bc }

  condition:
    any of them
}