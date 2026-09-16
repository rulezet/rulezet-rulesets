rule TTP_XOR_QUAD_CurrentVersionRun_201b {
  strings:
    $key_201b = { 73 74 [2] 57 7a [2] 7c 56 [2] 52 74 [2] 46 6f [2] 49 75 [2] 57 68 [2] 55 69 [2] 4e 6f [2] 52 68 [2] 4e 47 }

  condition:
    any of them
}