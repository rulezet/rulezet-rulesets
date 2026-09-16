rule TTP_XOR_QUAD_CurrentVersionRun_e1e1 {
  strings:
    $key_e1e1 = { b2 8e [2] 96 80 [2] bd ac [2] 93 8e [2] 87 95 [2] 88 8f [2] 96 92 [2] 94 93 [2] 8f 95 [2] 93 92 [2] 8f bd }

  condition:
    any of them
}