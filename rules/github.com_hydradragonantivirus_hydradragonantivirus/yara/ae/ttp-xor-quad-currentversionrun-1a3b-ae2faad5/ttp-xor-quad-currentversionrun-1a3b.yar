rule TTP_XOR_QUAD_CurrentVersionRun_1a3b {
  strings:
    $key_1a3b = { 49 54 [2] 6d 5a [2] 46 76 [2] 68 54 [2] 7c 4f [2] 73 55 [2] 6d 48 [2] 6f 49 [2] 74 4f [2] 68 48 [2] 74 67 }

  condition:
    any of them
}