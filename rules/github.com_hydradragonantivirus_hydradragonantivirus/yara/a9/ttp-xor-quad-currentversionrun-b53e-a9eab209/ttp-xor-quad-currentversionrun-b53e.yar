rule TTP_XOR_QUAD_CurrentVersionRun_b53e {
  strings:
    $key_b53e = { e6 51 [2] c2 5f [2] e9 73 [2] c7 51 [2] d3 4a [2] dc 50 [2] c2 4d [2] c0 4c [2] db 4a [2] c7 4d [2] db 62 }

  condition:
    any of them
}