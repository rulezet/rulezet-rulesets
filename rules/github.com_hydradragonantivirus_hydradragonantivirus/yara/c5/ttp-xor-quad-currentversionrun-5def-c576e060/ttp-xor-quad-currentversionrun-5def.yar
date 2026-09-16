rule TTP_XOR_QUAD_CurrentVersionRun_5def {
  strings:
    $key_5def = { 0e 80 [2] 2a 8e [2] 01 a2 [2] 2f 80 [2] 3b 9b [2] 34 81 [2] 2a 9c [2] 28 9d [2] 33 9b [2] 2f 9c [2] 33 b3 }

  condition:
    any of them
}