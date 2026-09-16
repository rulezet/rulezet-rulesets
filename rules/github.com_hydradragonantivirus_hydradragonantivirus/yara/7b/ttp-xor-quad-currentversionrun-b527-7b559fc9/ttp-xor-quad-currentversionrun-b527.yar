rule TTP_XOR_QUAD_CurrentVersionRun_b527 {
  strings:
    $key_b527 = { e6 48 [2] c2 46 [2] e9 6a [2] c7 48 [2] d3 53 [2] dc 49 [2] c2 54 [2] c0 55 [2] db 53 [2] c7 54 [2] db 7b }

  condition:
    any of them
}