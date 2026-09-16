rule TTP_XOR_QUAD_CurrentVersionRun_3b3b {
  strings:
    $key_3b3b = { 68 54 [2] 4c 5a [2] 67 76 [2] 49 54 [2] 5d 4f [2] 52 55 [2] 4c 48 [2] 4e 49 [2] 55 4f [2] 49 48 [2] 55 67 }

  condition:
    any of them
}