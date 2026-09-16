rule TTP_XOR_QUAD_CurrentVersionRun_52e9 {
  strings:
    $key_52e9 = { 01 86 [2] 25 88 [2] 0e a4 [2] 20 86 [2] 34 9d [2] 3b 87 [2] 25 9a [2] 27 9b [2] 3c 9d [2] 20 9a [2] 3c b5 }

  condition:
    any of them
}