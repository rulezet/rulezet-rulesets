rule TTP_XOR_QUAD_CurrentVersionRun_8f80 {
  strings:
    $key_8f80 = { dc ef [2] f8 e1 [2] d3 cd [2] fd ef [2] e9 f4 [2] e6 ee [2] f8 f3 [2] fa f2 [2] e1 f4 [2] fd f3 [2] e1 dc }

  condition:
    any of them
}