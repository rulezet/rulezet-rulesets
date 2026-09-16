rule TTP_XOR_QUAD_CurrentVersionRun_582e {
  strings:
    $key_582e = { 0b 41 [2] 2f 4f [2] 04 63 [2] 2a 41 [2] 3e 5a [2] 31 40 [2] 2f 5d [2] 2d 5c [2] 36 5a [2] 2a 5d [2] 36 72 }

  condition:
    any of them
}