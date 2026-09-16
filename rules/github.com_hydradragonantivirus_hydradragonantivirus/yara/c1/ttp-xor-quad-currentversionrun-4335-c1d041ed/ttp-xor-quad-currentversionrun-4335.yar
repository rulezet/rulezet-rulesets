rule TTP_XOR_QUAD_CurrentVersionRun_4335 {
  strings:
    $key_4335 = { 10 5a [2] 34 54 [2] 1f 78 [2] 31 5a [2] 25 41 [2] 2a 5b [2] 34 46 [2] 36 47 [2] 2d 41 [2] 31 46 [2] 2d 69 }

  condition:
    any of them
}