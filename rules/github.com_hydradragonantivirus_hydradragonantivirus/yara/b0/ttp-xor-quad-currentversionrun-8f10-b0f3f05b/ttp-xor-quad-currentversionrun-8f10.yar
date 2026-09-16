rule TTP_XOR_QUAD_CurrentVersionRun_8f10 {
  strings:
    $key_8f10 = { dc 7f [2] f8 71 [2] d3 5d [2] fd 7f [2] e9 64 [2] e6 7e [2] f8 63 [2] fa 62 [2] e1 64 [2] fd 63 [2] e1 4c }

  condition:
    any of them
}