rule TTP_XOR_QUAD_CurrentVersionRun_b513 {
  strings:
    $key_b513 = { e6 7c [2] c2 72 [2] e9 5e [2] c7 7c [2] d3 67 [2] dc 7d [2] c2 60 [2] c0 61 [2] db 67 [2] c7 60 [2] db 4f }

  condition:
    any of them
}