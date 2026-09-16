rule TTP_XOR_QUAD_CurrentVersionRun_707e {
  strings:
    $key_707e = { 23 11 [2] 07 1f [2] 2c 33 [2] 02 11 [2] 16 0a [2] 19 10 [2] 07 0d [2] 05 0c [2] 1e 0a [2] 02 0d [2] 1e 22 }

  condition:
    any of them
}