rule TTP_XOR_QUAD_CurrentVersionRun_12fb {
  strings:
    $key_12fb = { 41 94 [2] 65 9a [2] 4e b6 [2] 60 94 [2] 74 8f [2] 7b 95 [2] 65 88 [2] 67 89 [2] 7c 8f [2] 60 88 [2] 7c a7 }

  condition:
    any of them
}