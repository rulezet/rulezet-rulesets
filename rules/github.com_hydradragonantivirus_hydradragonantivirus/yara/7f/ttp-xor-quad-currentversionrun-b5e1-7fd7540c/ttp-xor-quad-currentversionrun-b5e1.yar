rule TTP_XOR_QUAD_CurrentVersionRun_b5e1 {
  strings:
    $key_b5e1 = { e6 8e [2] c2 80 [2] e9 ac [2] c7 8e [2] d3 95 [2] dc 8f [2] c2 92 [2] c0 93 [2] db 95 [2] c7 92 [2] db bd }

  condition:
    any of them
}