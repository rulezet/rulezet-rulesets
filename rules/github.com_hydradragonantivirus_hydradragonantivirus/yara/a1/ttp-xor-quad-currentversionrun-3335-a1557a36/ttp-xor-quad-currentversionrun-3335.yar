rule TTP_XOR_QUAD_CurrentVersionRun_3335 {
  strings:
    $key_3335 = { 60 5a [2] 44 54 [2] 6f 78 [2] 41 5a [2] 55 41 [2] 5a 5b [2] 44 46 [2] 46 47 [2] 5d 41 [2] 41 46 [2] 5d 69 }

  condition:
    any of them
}