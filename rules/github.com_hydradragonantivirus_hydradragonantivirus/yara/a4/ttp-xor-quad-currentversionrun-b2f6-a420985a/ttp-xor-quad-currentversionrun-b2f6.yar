rule TTP_XOR_QUAD_CurrentVersionRun_b2f6 {
  strings:
    $key_b2f6 = { e1 99 [2] c5 97 [2] ee bb [2] c0 99 [2] d4 82 [2] db 98 [2] c5 85 [2] c7 84 [2] dc 82 [2] c0 85 [2] dc aa }

  condition:
    any of them
}