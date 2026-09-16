rule TTP_XOR_QUAD_CurrentVersionRun_007e {
  strings:
    $key_007e = { 53 11 [2] 77 1f [2] 5c 33 [2] 72 11 [2] 66 0a [2] 69 10 [2] 77 0d [2] 75 0c [2] 6e 0a [2] 72 0d [2] 6e 22 }

  condition:
    any of them
}