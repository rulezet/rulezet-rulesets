rule TTP_XOR_QUAD_CurrentVersionRun_055e {
  strings:
    $key_055e = { 56 31 [2] 72 3f [2] 59 13 [2] 77 31 [2] 63 2a [2] 6c 30 [2] 72 2d [2] 70 2c [2] 6b 2a [2] 77 2d [2] 6b 02 }

  condition:
    any of them
}