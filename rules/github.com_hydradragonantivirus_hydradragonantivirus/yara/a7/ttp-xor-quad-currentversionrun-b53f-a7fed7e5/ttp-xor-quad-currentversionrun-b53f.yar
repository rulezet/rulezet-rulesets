rule TTP_XOR_QUAD_CurrentVersionRun_b53f {
  strings:
    $key_b53f = { e6 50 [2] c2 5e [2] e9 72 [2] c7 50 [2] d3 4b [2] dc 51 [2] c2 4c [2] c0 4d [2] db 4b [2] c7 4c [2] db 63 }

  condition:
    any of them
}