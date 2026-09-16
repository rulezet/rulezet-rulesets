rule TTP_XOR_QUAD_CurrentVersionRun_b50e {
  strings:
    $key_b50e = { e6 61 [2] c2 6f [2] e9 43 [2] c7 61 [2] d3 7a [2] dc 60 [2] c2 7d [2] c0 7c [2] db 7a [2] c7 7d [2] db 52 }

  condition:
    any of them
}