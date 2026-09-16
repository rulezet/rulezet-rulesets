rule TTP_XOR_QUAD_CurrentVersionRun_2778 {
  strings:
    $key_2778 = { 74 17 [2] 50 19 [2] 7b 35 [2] 55 17 [2] 41 0c [2] 4e 16 [2] 50 0b [2] 52 0a [2] 49 0c [2] 55 0b [2] 49 24 }

  condition:
    any of them
}