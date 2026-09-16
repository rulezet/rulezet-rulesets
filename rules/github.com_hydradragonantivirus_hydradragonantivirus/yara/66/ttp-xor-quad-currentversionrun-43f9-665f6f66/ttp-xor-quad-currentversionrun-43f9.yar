rule TTP_XOR_QUAD_CurrentVersionRun_43f9 {
  strings:
    $key_43f9 = { 10 96 [2] 34 98 [2] 1f b4 [2] 31 96 [2] 25 8d [2] 2a 97 [2] 34 8a [2] 36 8b [2] 2d 8d [2] 31 8a [2] 2d a5 }

  condition:
    any of them
}