rule TTP_XOR_QUAD_CurrentVersionRun_1d2e {
  strings:
    $key_1d2e = { 4e 41 [2] 6a 4f [2] 41 63 [2] 6f 41 [2] 7b 5a [2] 74 40 [2] 6a 5d [2] 68 5c [2] 73 5a [2] 6f 5d [2] 73 72 }

  condition:
    any of them
}