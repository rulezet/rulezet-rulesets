rule TTP_XOR_QUAD_CurrentVersionRun_8f22 {
  strings:
    $key_8f22 = { dc 4d [2] f8 43 [2] d3 6f [2] fd 4d [2] e9 56 [2] e6 4c [2] f8 51 [2] fa 50 [2] e1 56 [2] fd 51 [2] e1 7e }

  condition:
    any of them
}