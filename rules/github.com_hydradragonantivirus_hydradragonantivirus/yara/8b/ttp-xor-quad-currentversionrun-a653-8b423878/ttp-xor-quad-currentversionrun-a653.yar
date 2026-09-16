rule TTP_XOR_QUAD_CurrentVersionRun_a653 {
  strings:
    $key_a653 = { f5 3c [2] d1 32 [2] fa 1e [2] d4 3c [2] c0 27 [2] cf 3d [2] d1 20 [2] d3 21 [2] c8 27 [2] d4 20 [2] c8 0f }

  condition:
    any of them
}