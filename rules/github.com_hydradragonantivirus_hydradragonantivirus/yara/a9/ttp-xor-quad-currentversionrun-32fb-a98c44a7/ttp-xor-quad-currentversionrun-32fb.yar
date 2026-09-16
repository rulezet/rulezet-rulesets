rule TTP_XOR_QUAD_CurrentVersionRun_32fb {
  strings:
    $key_32fb = { 61 94 [2] 45 9a [2] 6e b6 [2] 40 94 [2] 54 8f [2] 5b 95 [2] 45 88 [2] 47 89 [2] 5c 8f [2] 40 88 [2] 5c a7 }

  condition:
    any of them
}