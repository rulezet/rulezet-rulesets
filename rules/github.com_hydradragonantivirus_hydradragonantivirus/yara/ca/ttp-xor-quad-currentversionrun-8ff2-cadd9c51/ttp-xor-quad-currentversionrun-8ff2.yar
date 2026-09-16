rule TTP_XOR_QUAD_CurrentVersionRun_8ff2 {
  strings:
    $key_8ff2 = { dc 9d [2] f8 93 [2] d3 bf [2] fd 9d [2] e9 86 [2] e6 9c [2] f8 81 [2] fa 80 [2] e1 86 [2] fd 81 [2] e1 ae }

  condition:
    any of them
}