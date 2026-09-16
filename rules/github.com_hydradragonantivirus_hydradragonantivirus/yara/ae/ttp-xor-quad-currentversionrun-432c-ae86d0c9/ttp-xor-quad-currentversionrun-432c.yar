rule TTP_XOR_QUAD_CurrentVersionRun_432c {
  strings:
    $key_432c = { 10 43 [2] 34 4d [2] 1f 61 [2] 31 43 [2] 25 58 [2] 2a 42 [2] 34 5f [2] 36 5e [2] 2d 58 [2] 31 5f [2] 2d 70 }

  condition:
    any of them
}