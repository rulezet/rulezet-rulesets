rule TTP_XOR_QUAD_CurrentVersionRun_a605 {
  strings:
    $key_a605 = { f5 6a [2] d1 64 [2] fa 48 [2] d4 6a [2] c0 71 [2] cf 6b [2] d1 76 [2] d3 77 [2] c8 71 [2] d4 76 [2] c8 59 }

  condition:
    any of them
}