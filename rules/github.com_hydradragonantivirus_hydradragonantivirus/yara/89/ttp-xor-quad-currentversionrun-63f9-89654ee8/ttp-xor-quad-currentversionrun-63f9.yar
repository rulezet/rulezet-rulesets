rule TTP_XOR_QUAD_CurrentVersionRun_63f9 {
  strings:
    $key_63f9 = { 30 96 [2] 14 98 [2] 3f b4 [2] 11 96 [2] 05 8d [2] 0a 97 [2] 14 8a [2] 16 8b [2] 0d 8d [2] 11 8a [2] 0d a5 }

  condition:
    any of them
}