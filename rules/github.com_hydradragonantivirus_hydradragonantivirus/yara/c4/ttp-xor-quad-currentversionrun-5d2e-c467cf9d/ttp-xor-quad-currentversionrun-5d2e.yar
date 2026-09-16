rule TTP_XOR_QUAD_CurrentVersionRun_5d2e {
  strings:
    $key_5d2e = { 0e 41 [2] 2a 4f [2] 01 63 [2] 2f 41 [2] 3b 5a [2] 34 40 [2] 2a 5d [2] 28 5c [2] 33 5a [2] 2f 5d [2] 33 72 }

  condition:
    any of them
}