rule TTP_XOR_QUAD_CurrentVersionRun_a6e0 {
  strings:
    $key_a6e0 = { f5 8f [2] d1 81 [2] fa ad [2] d4 8f [2] c0 94 [2] cf 8e [2] d1 93 [2] d3 92 [2] c8 94 [2] d4 93 [2] c8 bc }

  condition:
    any of them
}