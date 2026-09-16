rule TTP_XOR_QUAD_CurrentVersionRun_7f2e {
  strings:
    $key_7f2e = { 2c 41 [2] 08 4f [2] 23 63 [2] 0d 41 [2] 19 5a [2] 16 40 [2] 08 5d [2] 0a 5c [2] 11 5a [2] 0d 5d [2] 11 72 }

  condition:
    any of them
}