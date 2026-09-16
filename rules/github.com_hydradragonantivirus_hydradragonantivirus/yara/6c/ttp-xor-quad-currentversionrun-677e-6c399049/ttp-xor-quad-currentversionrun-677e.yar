rule TTP_XOR_QUAD_CurrentVersionRun_677e {
  strings:
    $key_677e = { 34 11 [2] 10 1f [2] 3b 33 [2] 15 11 [2] 01 0a [2] 0e 10 [2] 10 0d [2] 12 0c [2] 09 0a [2] 15 0d [2] 09 22 }

  condition:
    any of them
}