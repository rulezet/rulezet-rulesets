rule TTP_XOR_QUAD_CurrentVersionRun_f8ee {
  strings:
    $key_f8ee = { ab 81 [2] 8f 8f [2] a4 a3 [2] 8a 81 [2] 9e 9a [2] 91 80 [2] 8f 9d [2] 8d 9c [2] 96 9a [2] 8a 9d [2] 96 b2 }

  condition:
    any of them
}