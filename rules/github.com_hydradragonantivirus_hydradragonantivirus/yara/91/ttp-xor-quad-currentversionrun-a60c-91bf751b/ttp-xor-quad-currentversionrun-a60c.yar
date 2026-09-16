rule TTP_XOR_QUAD_CurrentVersionRun_a60c {
  strings:
    $key_a60c = { f5 63 [2] d1 6d [2] fa 41 [2] d4 63 [2] c0 78 [2] cf 62 [2] d1 7f [2] d3 7e [2] c8 78 [2] d4 7f [2] c8 50 }

  condition:
    any of them
}