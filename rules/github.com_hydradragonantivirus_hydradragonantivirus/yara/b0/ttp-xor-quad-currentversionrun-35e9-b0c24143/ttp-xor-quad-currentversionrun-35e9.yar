rule TTP_XOR_QUAD_CurrentVersionRun_35e9 {
  strings:
    $key_35e9 = { 66 86 [2] 42 88 [2] 69 a4 [2] 47 86 [2] 53 9d [2] 5c 87 [2] 42 9a [2] 40 9b [2] 5b 9d [2] 47 9a [2] 5b b5 }

  condition:
    any of them
}