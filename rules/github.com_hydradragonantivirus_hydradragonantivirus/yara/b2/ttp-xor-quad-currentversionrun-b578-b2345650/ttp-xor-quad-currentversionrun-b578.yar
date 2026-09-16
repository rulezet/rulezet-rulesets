rule TTP_XOR_QUAD_CurrentVersionRun_b578 {
  strings:
    $key_b578 = { e6 17 [2] c2 19 [2] e9 35 [2] c7 17 [2] d3 0c [2] dc 16 [2] c2 0b [2] c0 0a [2] db 0c [2] c7 0b [2] db 24 }

  condition:
    any of them
}