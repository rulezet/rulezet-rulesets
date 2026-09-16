rule TTP_XOR_QUAD_CurrentVersionRun_e5fb {
  strings:
    $key_e5fb = { b6 94 [2] 92 9a [2] b9 b6 [2] 97 94 [2] 83 8f [2] 8c 95 [2] 92 88 [2] 90 89 [2] 8b 8f [2] 97 88 [2] 8b a7 }

  condition:
    any of them
}