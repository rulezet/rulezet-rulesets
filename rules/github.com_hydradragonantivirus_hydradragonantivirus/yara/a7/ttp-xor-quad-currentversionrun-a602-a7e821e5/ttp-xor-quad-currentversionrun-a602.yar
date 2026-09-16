rule TTP_XOR_QUAD_CurrentVersionRun_a602 {
  strings:
    $key_a602 = { f5 6d [2] d1 63 [2] fa 4f [2] d4 6d [2] c0 76 [2] cf 6c [2] d1 71 [2] d3 70 [2] c8 76 [2] d4 71 [2] c8 5e }

  condition:
    any of them
}