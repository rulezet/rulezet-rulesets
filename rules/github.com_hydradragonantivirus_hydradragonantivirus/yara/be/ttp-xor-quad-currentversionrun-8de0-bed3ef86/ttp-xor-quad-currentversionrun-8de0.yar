rule TTP_XOR_QUAD_CurrentVersionRun_8de0 {
  strings:
    $key_8de0 = { de 8f [2] fa 81 [2] d1 ad [2] ff 8f [2] eb 94 [2] e4 8e [2] fa 93 [2] f8 92 [2] e3 94 [2] ff 93 [2] e3 bc }

  condition:
    any of them
}