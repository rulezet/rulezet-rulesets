rule TTP_XOR_QUAD_CurrentVersionRun_8fe3 {
  strings:
    $key_8fe3 = { dc 8c [2] f8 82 [2] d3 ae [2] fd 8c [2] e9 97 [2] e6 8d [2] f8 90 [2] fa 91 [2] e1 97 [2] fd 90 [2] e1 bf }

  condition:
    any of them
}