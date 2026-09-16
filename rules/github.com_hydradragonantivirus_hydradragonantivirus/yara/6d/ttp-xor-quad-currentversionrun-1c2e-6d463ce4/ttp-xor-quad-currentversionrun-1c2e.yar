rule TTP_XOR_QUAD_CurrentVersionRun_1c2e {
  strings:
    $key_1c2e = { 4f 41 [2] 6b 4f [2] 40 63 [2] 6e 41 [2] 7a 5a [2] 75 40 [2] 6b 5d [2] 69 5c [2] 72 5a [2] 6e 5d [2] 72 72 }

  condition:
    any of them
}