rule TTP_XOR_QUAD_CurrentVersionRun_8f82 {
  strings:
    $key_8f82 = { dc ed [2] f8 e3 [2] d3 cf [2] fd ed [2] e9 f6 [2] e6 ec [2] f8 f1 [2] fa f0 [2] e1 f6 [2] fd f1 [2] e1 de }

  condition:
    any of them
}