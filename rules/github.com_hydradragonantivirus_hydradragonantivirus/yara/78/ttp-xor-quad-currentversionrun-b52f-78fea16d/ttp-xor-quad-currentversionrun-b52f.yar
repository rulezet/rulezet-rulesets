rule TTP_XOR_QUAD_CurrentVersionRun_b52f {
  strings:
    $key_b52f = { e6 40 [2] c2 4e [2] e9 62 [2] c7 40 [2] d3 5b [2] dc 41 [2] c2 5c [2] c0 5d [2] db 5b [2] c7 5c [2] db 73 }

  condition:
    any of them
}