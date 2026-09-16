rule TTP_XOR_QUAD_CurrentVersionRun_105e {
  strings:
    $key_105e = { 43 31 [2] 67 3f [2] 4c 13 [2] 62 31 [2] 76 2a [2] 79 30 [2] 67 2d [2] 65 2c [2] 7e 2a [2] 62 2d [2] 7e 02 }

  condition:
    any of them
}