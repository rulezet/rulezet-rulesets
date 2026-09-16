rule TTP_XOR_QUAD_CurrentVersionRun_b500 {
  strings:
    $key_b500 = { e6 6f [2] c2 61 [2] e9 4d [2] c7 6f [2] d3 74 [2] dc 6e [2] c2 73 [2] c0 72 [2] db 74 [2] c7 73 [2] db 5c }

  condition:
    any of them
}