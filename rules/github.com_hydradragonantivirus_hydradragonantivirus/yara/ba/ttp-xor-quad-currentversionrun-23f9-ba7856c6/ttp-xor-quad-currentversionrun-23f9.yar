rule TTP_XOR_QUAD_CurrentVersionRun_23f9 {
  strings:
    $key_23f9 = { 70 96 [2] 54 98 [2] 7f b4 [2] 51 96 [2] 45 8d [2] 4a 97 [2] 54 8a [2] 56 8b [2] 4d 8d [2] 51 8a [2] 4d a5 }

  condition:
    any of them
}