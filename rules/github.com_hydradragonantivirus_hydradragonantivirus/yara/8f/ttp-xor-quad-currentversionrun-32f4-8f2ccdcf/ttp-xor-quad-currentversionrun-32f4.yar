rule TTP_XOR_QUAD_CurrentVersionRun_32f4 {
  strings:
    $key_32f4 = { 61 9b [2] 45 95 [2] 6e b9 [2] 40 9b [2] 54 80 [2] 5b 9a [2] 45 87 [2] 47 86 [2] 5c 80 [2] 40 87 [2] 5c a8 }

  condition:
    any of them
}