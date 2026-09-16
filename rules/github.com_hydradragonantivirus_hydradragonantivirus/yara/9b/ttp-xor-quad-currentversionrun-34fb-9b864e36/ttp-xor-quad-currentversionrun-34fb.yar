rule TTP_XOR_QUAD_CurrentVersionRun_34fb {
  strings:
    $key_34fb = { 67 94 [2] 43 9a [2] 68 b6 [2] 46 94 [2] 52 8f [2] 5d 95 [2] 43 88 [2] 41 89 [2] 5a 8f [2] 46 88 [2] 5a a7 }

  condition:
    any of them
}