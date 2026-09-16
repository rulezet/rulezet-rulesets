rule TTP_XOR_QUAD_CurrentVersionRun_257e {
  strings:
    $key_257e = { 76 11 [2] 52 1f [2] 79 33 [2] 57 11 [2] 43 0a [2] 4c 10 [2] 52 0d [2] 50 0c [2] 4b 0a [2] 57 0d [2] 4b 22 }

  condition:
    any of them
}