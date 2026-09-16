rule TTP_XOR_QUAD_CurrentVersionRun_3b4b {
  strings:
    $key_3b4b = { 68 24 [2] 4c 2a [2] 67 06 [2] 49 24 [2] 5d 3f [2] 52 25 [2] 4c 38 [2] 4e 39 [2] 55 3f [2] 49 38 [2] 55 17 }

  condition:
    any of them
}