rule TTP_XOR_QUAD_CurrentVersionRun_367e {
  strings:
    $key_367e = { 65 11 [2] 41 1f [2] 6a 33 [2] 44 11 [2] 50 0a [2] 5f 10 [2] 41 0d [2] 43 0c [2] 58 0a [2] 44 0d [2] 58 22 }

  condition:
    any of them
}