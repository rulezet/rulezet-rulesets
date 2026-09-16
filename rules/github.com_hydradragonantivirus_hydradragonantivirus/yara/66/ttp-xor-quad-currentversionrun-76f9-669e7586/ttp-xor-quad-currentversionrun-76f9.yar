rule TTP_XOR_QUAD_CurrentVersionRun_76f9 {
  strings:
    $key_76f9 = { 25 96 [2] 01 98 [2] 2a b4 [2] 04 96 [2] 10 8d [2] 1f 97 [2] 01 8a [2] 03 8b [2] 18 8d [2] 04 8a [2] 18 a5 }

  condition:
    any of them
}