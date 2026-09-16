rule TTP_XOR_QUAD_CurrentVersionRun_62e8 {
  strings:
    $key_62e8 = { 31 87 [2] 15 89 [2] 3e a5 [2] 10 87 [2] 04 9c [2] 0b 86 [2] 15 9b [2] 17 9a [2] 0c 9c [2] 10 9b [2] 0c b4 }

  condition:
    any of them
}