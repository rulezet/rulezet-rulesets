rule TTP_XOR_QUAD_CurrentVersionRun_0ae8 {
  strings:
    $key_0ae8 = { 59 87 [2] 7d 89 [2] 56 a5 [2] 78 87 [2] 6c 9c [2] 63 86 [2] 7d 9b [2] 7f 9a [2] 64 9c [2] 78 9b [2] 64 b4 }

  condition:
    any of them
}