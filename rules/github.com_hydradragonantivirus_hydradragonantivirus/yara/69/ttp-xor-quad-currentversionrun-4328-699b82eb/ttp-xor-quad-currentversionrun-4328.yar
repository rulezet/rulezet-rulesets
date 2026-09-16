rule TTP_XOR_QUAD_CurrentVersionRun_4328 {
  strings:
    $key_4328 = { 10 47 [2] 34 49 [2] 1f 65 [2] 31 47 [2] 25 5c [2] 2a 46 [2] 34 5b [2] 36 5a [2] 2d 5c [2] 31 5b [2] 2d 74 }

  condition:
    any of them
}