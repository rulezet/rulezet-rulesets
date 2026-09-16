rule TTP_XOR_QUAD_CurrentVersionRun_0de8 {
  strings:
    $key_0de8 = { 5e 87 [2] 7a 89 [2] 51 a5 [2] 7f 87 [2] 6b 9c [2] 64 86 [2] 7a 9b [2] 78 9a [2] 63 9c [2] 7f 9b [2] 63 b4 }

  condition:
    any of them
}