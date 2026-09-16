rule TTP_XOR_QUAD_CurrentVersionRun_33fb {
  strings:
    $key_33fb = { 60 94 [2] 44 9a [2] 6f b6 [2] 41 94 [2] 55 8f [2] 5a 95 [2] 44 88 [2] 46 89 [2] 5d 8f [2] 41 88 [2] 5d a7 }

  condition:
    any of them
}