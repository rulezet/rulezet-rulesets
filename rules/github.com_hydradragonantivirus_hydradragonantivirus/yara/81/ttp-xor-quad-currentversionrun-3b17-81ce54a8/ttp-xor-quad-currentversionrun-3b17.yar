rule TTP_XOR_QUAD_CurrentVersionRun_3b17 {
  strings:
    $key_3b17 = { 68 78 [2] 4c 76 [2] 67 5a [2] 49 78 [2] 5d 63 [2] 52 79 [2] 4c 64 [2] 4e 65 [2] 55 63 [2] 49 64 [2] 55 4b }

  condition:
    any of them
}