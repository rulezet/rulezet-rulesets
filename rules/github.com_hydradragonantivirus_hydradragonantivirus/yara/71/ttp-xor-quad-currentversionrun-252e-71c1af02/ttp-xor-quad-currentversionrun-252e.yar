rule TTP_XOR_QUAD_CurrentVersionRun_252e {
  strings:
    $key_252e = { 76 41 [2] 52 4f [2] 79 63 [2] 57 41 [2] 43 5a [2] 4c 40 [2] 52 5d [2] 50 5c [2] 4b 5a [2] 57 5d [2] 4b 72 }

  condition:
    any of them
}