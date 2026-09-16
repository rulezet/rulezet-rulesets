rule TTP_XOR_QUAD_CurrentVersionRun_33e9 {
  strings:
    $key_33e9 = { 60 86 [2] 44 88 [2] 6f a4 [2] 41 86 [2] 55 9d [2] 5a 87 [2] 44 9a [2] 46 9b [2] 5d 9d [2] 41 9a [2] 5d b5 }

  condition:
    any of them
}