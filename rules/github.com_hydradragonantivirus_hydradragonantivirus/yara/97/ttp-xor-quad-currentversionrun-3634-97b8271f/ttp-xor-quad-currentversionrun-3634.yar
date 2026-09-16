rule TTP_XOR_QUAD_CurrentVersionRun_3634 {
  strings:
    $key_3634 = { 65 5b [2] 41 55 [2] 6a 79 [2] 44 5b [2] 50 40 [2] 5f 5a [2] 41 47 [2] 43 46 [2] 58 40 [2] 44 47 [2] 58 68 }

  condition:
    any of them
}