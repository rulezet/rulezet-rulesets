rule TTP_XOR_QUAD_CurrentVersionRun_16e8 {
  strings:
    $key_16e8 = { 45 87 [2] 61 89 [2] 4a a5 [2] 64 87 [2] 70 9c [2] 7f 86 [2] 61 9b [2] 63 9a [2] 78 9c [2] 64 9b [2] 78 b4 }

  condition:
    any of them
}