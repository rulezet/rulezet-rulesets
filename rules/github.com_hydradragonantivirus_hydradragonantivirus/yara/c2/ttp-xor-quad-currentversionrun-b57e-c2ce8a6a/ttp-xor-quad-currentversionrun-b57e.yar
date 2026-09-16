rule TTP_XOR_QUAD_CurrentVersionRun_b57e {
  strings:
    $key_b57e = { e6 11 [2] c2 1f [2] e9 33 [2] c7 11 [2] d3 0a [2] dc 10 [2] c2 0d [2] c0 0c [2] db 0a [2] c7 0d [2] db 22 }

  condition:
    any of them
}