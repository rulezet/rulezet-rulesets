rule TTP_XOR_QUAD_CurrentVersionRun_43e5 {
  strings:
    $key_43e5 = { 10 8a [2] 34 84 [2] 1f a8 [2] 31 8a [2] 25 91 [2] 2a 8b [2] 34 96 [2] 36 97 [2] 2d 91 [2] 31 96 [2] 2d b9 }

  condition:
    any of them
}