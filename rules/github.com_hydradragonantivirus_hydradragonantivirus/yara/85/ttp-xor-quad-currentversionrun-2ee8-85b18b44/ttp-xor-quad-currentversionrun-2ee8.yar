rule TTP_XOR_QUAD_CurrentVersionRun_2ee8 {
  strings:
    $key_2ee8 = { 7d 87 [2] 59 89 [2] 72 a5 [2] 5c 87 [2] 48 9c [2] 47 86 [2] 59 9b [2] 5b 9a [2] 40 9c [2] 5c 9b [2] 40 b4 }

  condition:
    any of them
}