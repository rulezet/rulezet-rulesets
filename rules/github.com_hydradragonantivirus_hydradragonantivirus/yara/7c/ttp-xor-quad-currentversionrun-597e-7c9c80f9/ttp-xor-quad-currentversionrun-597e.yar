rule TTP_XOR_QUAD_CurrentVersionRun_597e {
  strings:
    $key_597e = { 0a 11 [2] 2e 1f [2] 05 33 [2] 2b 11 [2] 3f 0a [2] 30 10 [2] 2e 0d [2] 2c 0c [2] 37 0a [2] 2b 0d [2] 37 22 }

  condition:
    any of them
}