rule TTP_XOR_QUAD_CurrentVersionRun_35e8 {
  strings:
    $key_35e8 = { 66 87 [2] 42 89 [2] 69 a5 [2] 47 87 [2] 53 9c [2] 5c 86 [2] 42 9b [2] 40 9a [2] 5b 9c [2] 47 9b [2] 5b b4 }

  condition:
    any of them
}