rule TTP_XOR_QUAD_CurrentVersionRun_b2f7 {
  strings:
    $key_b2f7 = { e1 98 [2] c5 96 [2] ee ba [2] c0 98 [2] d4 83 [2] db 99 [2] c5 84 [2] c7 85 [2] dc 83 [2] c0 84 [2] dc ab }

  condition:
    any of them
}