rule TTP_XOR_QUAD_CurrentVersionRun_3b27 {
  strings:
    $key_3b27 = { 68 48 [2] 4c 46 [2] 67 6a [2] 49 48 [2] 5d 53 [2] 52 49 [2] 4c 54 [2] 4e 55 [2] 55 53 [2] 49 54 [2] 55 7b }

  condition:
    any of them
}