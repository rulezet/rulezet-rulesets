rule TTP_XOR_QUAD_CurrentVersionRun_52e8 {
  strings:
    $key_52e8 = { 01 87 [2] 25 89 [2] 0e a5 [2] 20 87 [2] 34 9c [2] 3b 86 [2] 25 9b [2] 27 9a [2] 3c 9c [2] 20 9b [2] 3c b4 }

  condition:
    any of them
}