rule TTP_XOR_QUAD_CurrentVersionRun_b533 {
  strings:
    $key_b533 = { e6 5c [2] c2 52 [2] e9 7e [2] c7 5c [2] d3 47 [2] dc 5d [2] c2 40 [2] c0 41 [2] db 47 [2] c7 40 [2] db 6f }

  condition:
    any of them
}