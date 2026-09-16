rule TTP_XOR_QUAD_CurrentVersionRun_fa14 {
  strings:
    $key_fa14 = { a9 7b [2] 8d 75 [2] a6 59 [2] 88 7b [2] 9c 60 [2] 93 7a [2] 8d 67 [2] 8f 66 [2] 94 60 [2] 88 67 [2] 94 48 }

  condition:
    any of them
}