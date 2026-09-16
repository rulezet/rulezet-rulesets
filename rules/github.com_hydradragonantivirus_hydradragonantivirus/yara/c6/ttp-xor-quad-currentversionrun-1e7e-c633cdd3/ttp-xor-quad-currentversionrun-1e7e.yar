rule TTP_XOR_QUAD_CurrentVersionRun_1e7e {
  strings:
    $key_1e7e = { 4d 11 [2] 69 1f [2] 42 33 [2] 6c 11 [2] 78 0a [2] 77 10 [2] 69 0d [2] 6b 0c [2] 70 0a [2] 6c 0d [2] 70 22 }

  condition:
    any of them
}