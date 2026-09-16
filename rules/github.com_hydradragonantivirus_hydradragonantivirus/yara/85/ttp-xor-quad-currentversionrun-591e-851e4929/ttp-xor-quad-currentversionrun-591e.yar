rule TTP_XOR_QUAD_CurrentVersionRun_591e {
  strings:
    $key_591e = { 0a 71 [2] 2e 7f [2] 05 53 [2] 2b 71 [2] 3f 6a [2] 30 70 [2] 2e 6d [2] 2c 6c [2] 37 6a [2] 2b 6d [2] 37 42 }

  condition:
    any of them
}