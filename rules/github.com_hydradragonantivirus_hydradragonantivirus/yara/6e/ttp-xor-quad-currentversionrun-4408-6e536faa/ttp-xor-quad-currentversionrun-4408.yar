rule TTP_XOR_QUAD_CurrentVersionRun_4408 {
  strings:
    $key_4408 = { 17 67 [2] 33 69 [2] 18 45 [2] 36 67 [2] 22 7c [2] 2d 66 [2] 33 7b [2] 31 7a [2] 2a 7c [2] 36 7b [2] 2a 54 }

  condition:
    any of them
}