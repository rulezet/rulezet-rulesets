rule TTP_XOR_QUAD_CurrentVersionRun_583e {
  strings:
    $key_583e = { 0b 51 [2] 2f 5f [2] 04 73 [2] 2a 51 [2] 3e 4a [2] 31 50 [2] 2f 4d [2] 2d 4c [2] 36 4a [2] 2a 4d [2] 36 62 }

  condition:
    any of them
}