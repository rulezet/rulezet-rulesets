rule TTP_XOR_QUAD_CurrentVersionRun_5517 {
  strings:
    $key_5517 = { 06 78 [2] 22 76 [2] 09 5a [2] 27 78 [2] 33 63 [2] 3c 79 [2] 22 64 [2] 20 65 [2] 3b 63 [2] 27 64 [2] 3b 4b }

  condition:
    any of them
}