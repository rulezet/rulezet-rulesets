rule TTP_XOR_QUAD_CurrentVersionRun_b50b {
  strings:
    $key_b50b = { e6 64 [2] c2 6a [2] e9 46 [2] c7 64 [2] d3 7f [2] dc 65 [2] c2 78 [2] c0 79 [2] db 7f [2] c7 78 [2] db 57 }

  condition:
    any of them
}