rule TTP_XOR_QUAD_CurrentVersionRun_fce0 {
  strings:
    $key_fce0 = { af 8f [2] 8b 81 [2] a0 ad [2] 8e 8f [2] 9a 94 [2] 95 8e [2] 8b 93 [2] 89 92 [2] 92 94 [2] 8e 93 [2] 92 bc }

  condition:
    any of them
}