rule TTP_XOR_QUAD_CurrentVersionRun_522e {
  strings:
    $key_522e = { 01 41 [2] 25 4f [2] 0e 63 [2] 20 41 [2] 34 5a [2] 3b 40 [2] 25 5d [2] 27 5c [2] 3c 5a [2] 20 5d [2] 3c 72 }

  condition:
    any of them
}