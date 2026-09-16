rule TTP_XOR_QUAD_CurrentVersionRun_b5e7 {
  strings:
    $key_b5e7 = { e6 88 [2] c2 86 [2] e9 aa [2] c7 88 [2] d3 93 [2] dc 89 [2] c2 94 [2] c0 95 [2] db 93 [2] c7 94 [2] db bb }

  condition:
    any of them
}