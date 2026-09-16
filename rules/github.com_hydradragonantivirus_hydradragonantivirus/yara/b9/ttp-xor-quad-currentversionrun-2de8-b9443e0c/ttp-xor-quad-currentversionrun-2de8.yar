rule TTP_XOR_QUAD_CurrentVersionRun_2de8 {
  strings:
    $key_2de8 = { 7e 87 [2] 5a 89 [2] 71 a5 [2] 5f 87 [2] 4b 9c [2] 44 86 [2] 5a 9b [2] 58 9a [2] 43 9c [2] 5f 9b [2] 43 b4 }

  condition:
    any of them
}