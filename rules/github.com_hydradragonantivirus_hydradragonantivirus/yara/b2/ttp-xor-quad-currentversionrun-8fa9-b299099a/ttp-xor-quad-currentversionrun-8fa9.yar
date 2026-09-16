rule TTP_XOR_QUAD_CurrentVersionRun_8fa9 {
  strings:
    $key_8fa9 = { dc c6 [2] f8 c8 [2] d3 e4 [2] fd c6 [2] e9 dd [2] e6 c7 [2] f8 da [2] fa db [2] e1 dd [2] fd da [2] e1 f5 }

  condition:
    any of them
}