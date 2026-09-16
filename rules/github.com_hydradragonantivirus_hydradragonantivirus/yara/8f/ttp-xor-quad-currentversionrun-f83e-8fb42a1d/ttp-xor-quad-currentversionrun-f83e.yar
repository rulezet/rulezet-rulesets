rule TTP_XOR_QUAD_CurrentVersionRun_f83e {
  strings:
    $key_f83e = { ab 51 [2] 8f 5f [2] a4 73 [2] 8a 51 [2] 9e 4a [2] 91 50 [2] 8f 4d [2] 8d 4c [2] 96 4a [2] 8a 4d [2] 96 62 }

  condition:
    any of them
}