rule TTP_XOR_QUAD_CurrentVersionRun_200b {
  strings:
    $key_200b = { 73 64 [2] 57 6a [2] 7c 46 [2] 52 64 [2] 46 7f [2] 49 65 [2] 57 78 [2] 55 79 [2] 4e 7f [2] 52 78 [2] 4e 57 }

  condition:
    any of them
}