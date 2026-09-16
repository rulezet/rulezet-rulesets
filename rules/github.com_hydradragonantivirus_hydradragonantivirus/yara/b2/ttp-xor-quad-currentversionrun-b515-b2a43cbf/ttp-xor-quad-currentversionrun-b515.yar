rule TTP_XOR_QUAD_CurrentVersionRun_b515 {
  strings:
    $key_b515 = { e6 7a [2] c2 74 [2] e9 58 [2] c7 7a [2] d3 61 [2] dc 7b [2] c2 66 [2] c0 67 [2] db 61 [2] c7 66 [2] db 49 }

  condition:
    any of them
}