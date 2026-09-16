rule TTP_XOR_QUAD_CurrentVersionRun_e9ee {
  strings:
    $key_e9ee = { ba 81 [2] 9e 8f [2] b5 a3 [2] 9b 81 [2] 8f 9a [2] 80 80 [2] 9e 9d [2] 9c 9c [2] 87 9a [2] 9b 9d [2] 87 b2 }

  condition:
    any of them
}