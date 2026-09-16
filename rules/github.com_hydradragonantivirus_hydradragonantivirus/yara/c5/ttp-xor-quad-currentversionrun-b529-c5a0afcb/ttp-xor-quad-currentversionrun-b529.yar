rule TTP_XOR_QUAD_CurrentVersionRun_b529 {
  strings:
    $key_b529 = { e6 46 [2] c2 48 [2] e9 64 [2] c7 46 [2] d3 5d [2] dc 47 [2] c2 5a [2] c0 5b [2] db 5d [2] c7 5a [2] db 75 }

  condition:
    any of them
}