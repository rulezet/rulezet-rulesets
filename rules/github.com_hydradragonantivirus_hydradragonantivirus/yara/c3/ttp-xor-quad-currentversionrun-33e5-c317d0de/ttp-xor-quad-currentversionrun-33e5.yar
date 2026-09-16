rule TTP_XOR_QUAD_CurrentVersionRun_33e5 {
  strings:
    $key_33e5 = { 60 8a [2] 44 84 [2] 6f a8 [2] 41 8a [2] 55 91 [2] 5a 8b [2] 44 96 [2] 46 97 [2] 5d 91 [2] 41 96 [2] 5d b9 }

  condition:
    any of them
}