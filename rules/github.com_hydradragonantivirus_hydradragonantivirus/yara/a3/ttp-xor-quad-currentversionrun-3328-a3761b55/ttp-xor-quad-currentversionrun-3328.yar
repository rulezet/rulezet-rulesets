rule TTP_XOR_QUAD_CurrentVersionRun_3328 {
  strings:
    $key_3328 = { 60 47 [2] 44 49 [2] 6f 65 [2] 41 47 [2] 55 5c [2] 5a 46 [2] 44 5b [2] 46 5a [2] 5d 5c [2] 41 5b [2] 5d 74 }

  condition:
    any of them
}