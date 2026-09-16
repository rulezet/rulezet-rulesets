rule TTP_XOR_QUAD_CurrentVersionRun_13f9 {
  strings:
    $key_13f9 = { 40 96 [2] 64 98 [2] 4f b4 [2] 61 96 [2] 75 8d [2] 7a 97 [2] 64 8a [2] 66 8b [2] 7d 8d [2] 61 8a [2] 7d a5 }

  condition:
    any of them
}