rule TTP_XOR_QUAD_CurrentVersionRun_22e8 {
  strings:
    $key_22e8 = { 71 87 [2] 55 89 [2] 7e a5 [2] 50 87 [2] 44 9c [2] 4b 86 [2] 55 9b [2] 57 9a [2] 4c 9c [2] 50 9b [2] 4c b4 }

  condition:
    any of them
}