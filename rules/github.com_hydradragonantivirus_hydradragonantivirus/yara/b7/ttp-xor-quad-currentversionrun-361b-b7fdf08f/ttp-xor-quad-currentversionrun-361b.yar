rule TTP_XOR_QUAD_CurrentVersionRun_361b {
  strings:
    $key_361b = { 65 74 [2] 41 7a [2] 6a 56 [2] 44 74 [2] 50 6f [2] 5f 75 [2] 41 68 [2] 43 69 [2] 58 6f [2] 44 68 [2] 58 47 }

  condition:
    any of them
}