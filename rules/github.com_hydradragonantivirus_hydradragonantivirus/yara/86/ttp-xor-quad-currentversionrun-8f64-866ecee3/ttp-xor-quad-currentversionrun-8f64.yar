rule TTP_XOR_QUAD_CurrentVersionRun_8f64 {
  strings:
    $key_8f64 = { dc 0b [2] f8 05 [2] d3 29 [2] fd 0b [2] e9 10 [2] e6 0a [2] f8 17 [2] fa 16 [2] e1 10 [2] fd 17 [2] e1 38 }

  condition:
    any of them
}