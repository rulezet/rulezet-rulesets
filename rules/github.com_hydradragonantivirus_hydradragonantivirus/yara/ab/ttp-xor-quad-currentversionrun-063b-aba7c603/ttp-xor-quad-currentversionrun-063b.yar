rule TTP_XOR_QUAD_CurrentVersionRun_063b {
  strings:
    $key_063b = { 55 54 [2] 71 5a [2] 5a 76 [2] 74 54 [2] 60 4f [2] 6f 55 [2] 71 48 [2] 73 49 [2] 68 4f [2] 74 48 [2] 68 67 }

  condition:
    any of them
}