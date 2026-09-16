rule TTP_XOR_QUAD_CurrentVersionRun_14f9 {
  strings:
    $key_14f9 = { 47 96 [2] 63 98 [2] 48 b4 [2] 66 96 [2] 72 8d [2] 7d 97 [2] 63 8a [2] 61 8b [2] 7a 8d [2] 66 8a [2] 7a a5 }

  condition:
    any of them
}