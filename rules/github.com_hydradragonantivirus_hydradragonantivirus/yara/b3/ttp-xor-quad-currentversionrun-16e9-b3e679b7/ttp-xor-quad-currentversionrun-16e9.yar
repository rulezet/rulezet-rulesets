rule TTP_XOR_QUAD_CurrentVersionRun_16e9 {
  strings:
    $key_16e9 = { 45 86 [2] 61 88 [2] 4a a4 [2] 64 86 [2] 70 9d [2] 7f 87 [2] 61 9a [2] 63 9b [2] 78 9d [2] 64 9a [2] 78 b5 }

  condition:
    any of them
}