rule TTP_XOR_QUAD_CurrentVersionRun_76f8 {
  strings:
    $key_76f8 = { 25 97 [2] 01 99 [2] 2a b5 [2] 04 97 [2] 10 8c [2] 1f 96 [2] 01 8b [2] 03 8a [2] 18 8c [2] 04 8b [2] 18 a4 }

  condition:
    any of them
}