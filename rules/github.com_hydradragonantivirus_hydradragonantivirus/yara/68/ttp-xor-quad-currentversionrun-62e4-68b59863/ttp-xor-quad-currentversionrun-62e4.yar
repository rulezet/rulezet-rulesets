rule TTP_XOR_QUAD_CurrentVersionRun_62e4 {
  strings:
    $key_62e4 = { 31 8b [2] 15 85 [2] 3e a9 [2] 10 8b [2] 04 90 [2] 0b 8a [2] 15 97 [2] 17 96 [2] 0c 90 [2] 10 97 [2] 0c b8 }

  condition:
    any of them
}