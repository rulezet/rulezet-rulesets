rule TTP_XOR_QUAD_CurrentVersionRun_b541 {
  strings:
    $key_b541 = { e6 2e [2] c2 20 [2] e9 0c [2] c7 2e [2] d3 35 [2] dc 2f [2] c2 32 [2] c0 33 [2] db 35 [2] c7 32 [2] db 1d }

  condition:
    any of them
}