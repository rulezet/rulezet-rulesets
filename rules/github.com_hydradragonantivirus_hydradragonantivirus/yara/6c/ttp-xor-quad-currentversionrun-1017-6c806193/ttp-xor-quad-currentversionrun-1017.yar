rule TTP_XOR_QUAD_CurrentVersionRun_1017 {
  strings:
    $key_1017 = { 43 78 [2] 67 76 [2] 4c 5a [2] 62 78 [2] 76 63 [2] 79 79 [2] 67 64 [2] 65 65 [2] 7e 63 [2] 62 64 [2] 7e 4b }

  condition:
    any of them
}