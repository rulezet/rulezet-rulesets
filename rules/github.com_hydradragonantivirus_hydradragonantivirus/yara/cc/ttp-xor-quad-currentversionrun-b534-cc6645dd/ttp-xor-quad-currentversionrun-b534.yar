rule TTP_XOR_QUAD_CurrentVersionRun_b534 {
  strings:
    $key_b534 = { e6 5b [2] c2 55 [2] e9 79 [2] c7 5b [2] d3 40 [2] dc 5a [2] c2 47 [2] c0 46 [2] db 40 [2] c7 47 [2] db 68 }

  condition:
    any of them
}