rule TTP_XOR_QUAD_CurrentVersionRun_b52e {
  strings:
    $key_b52e = { e6 41 [2] c2 4f [2] e9 63 [2] c7 41 [2] d3 5a [2] dc 40 [2] c2 5d [2] c0 5c [2] db 5a [2] c7 5d [2] db 72 }

  condition:
    any of them
}