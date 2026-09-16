rule TTP_XOR_QUAD_CurrentVersionRun_b2e1 {
  strings:
    $key_b2e1 = { e1 8e [2] c5 80 [2] ee ac [2] c0 8e [2] d4 95 [2] db 8f [2] c5 92 [2] c7 93 [2] dc 95 [2] c0 92 [2] dc bd }

  condition:
    any of them
}