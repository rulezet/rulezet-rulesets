rule TTP_XOR_QUAD_CurrentVersionRun_b530 {
  strings:
    $key_b530 = { e6 5f [2] c2 51 [2] e9 7d [2] c7 5f [2] d3 44 [2] dc 5e [2] c2 43 [2] c0 42 [2] db 44 [2] c7 43 [2] db 6c }

  condition:
    any of them
}