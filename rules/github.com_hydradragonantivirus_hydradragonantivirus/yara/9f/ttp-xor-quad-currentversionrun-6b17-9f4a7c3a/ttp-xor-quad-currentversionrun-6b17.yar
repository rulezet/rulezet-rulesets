rule TTP_XOR_QUAD_CurrentVersionRun_6b17 {
  strings:
    $key_6b17 = { 38 78 [2] 1c 76 [2] 37 5a [2] 19 78 [2] 0d 63 [2] 02 79 [2] 1c 64 [2] 1e 65 [2] 05 63 [2] 19 64 [2] 05 4b }

  condition:
    any of them
}