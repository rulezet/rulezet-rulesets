rule TTP_XOR_QUAD_CurrentVersionRun_14f8 {
  strings:
    $key_14f8 = { 47 97 [2] 63 99 [2] 48 b5 [2] 66 97 [2] 72 8c [2] 7d 96 [2] 63 8b [2] 61 8a [2] 7a 8c [2] 66 8b [2] 7a a4 }

  condition:
    any of them
}