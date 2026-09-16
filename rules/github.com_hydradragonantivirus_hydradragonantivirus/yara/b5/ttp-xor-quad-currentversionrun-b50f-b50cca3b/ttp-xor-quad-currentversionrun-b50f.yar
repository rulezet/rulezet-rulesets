rule TTP_XOR_QUAD_CurrentVersionRun_b50f {
  strings:
    $key_b50f = { e6 60 [2] c2 6e [2] e9 42 [2] c7 60 [2] d3 7b [2] dc 61 [2] c2 7c [2] c0 7d [2] db 7b [2] c7 7c [2] db 53 }

  condition:
    any of them
}