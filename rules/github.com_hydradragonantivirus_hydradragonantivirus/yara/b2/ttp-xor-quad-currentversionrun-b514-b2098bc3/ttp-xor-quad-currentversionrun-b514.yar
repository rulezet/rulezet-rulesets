rule TTP_XOR_QUAD_CurrentVersionRun_b514 {
  strings:
    $key_b514 = { e6 7b [2] c2 75 [2] e9 59 [2] c7 7b [2] d3 60 [2] dc 7a [2] c2 67 [2] c0 66 [2] db 60 [2] c7 67 [2] db 48 }

  condition:
    any of them
}