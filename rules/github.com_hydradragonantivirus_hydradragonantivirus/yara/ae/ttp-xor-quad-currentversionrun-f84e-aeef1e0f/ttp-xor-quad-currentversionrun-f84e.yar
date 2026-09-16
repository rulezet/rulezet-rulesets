rule TTP_XOR_QUAD_CurrentVersionRun_f84e {
  strings:
    $key_f84e = { ab 21 [2] 8f 2f [2] a4 03 [2] 8a 21 [2] 9e 3a [2] 91 20 [2] 8f 3d [2] 8d 3c [2] 96 3a [2] 8a 3d [2] 96 12 }

  condition:
    any of them
}