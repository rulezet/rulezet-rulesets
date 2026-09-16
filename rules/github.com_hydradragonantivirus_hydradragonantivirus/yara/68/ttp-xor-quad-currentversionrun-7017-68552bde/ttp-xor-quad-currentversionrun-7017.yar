rule TTP_XOR_QUAD_CurrentVersionRun_7017 {
  strings:
    $key_7017 = { 23 78 [2] 07 76 [2] 2c 5a [2] 02 78 [2] 16 63 [2] 19 79 [2] 07 64 [2] 05 65 [2] 1e 63 [2] 02 64 [2] 1e 4b }

  condition:
    any of them
}