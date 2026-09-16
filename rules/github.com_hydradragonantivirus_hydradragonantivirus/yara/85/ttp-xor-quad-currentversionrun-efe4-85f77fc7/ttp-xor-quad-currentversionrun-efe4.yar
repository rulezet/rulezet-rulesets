rule TTP_XOR_QUAD_CurrentVersionRun_efe4 {
  strings:
    $key_efe4 = { bc 8b [2] 98 85 [2] b3 a9 [2] 9d 8b [2] 89 90 [2] 86 8a [2] 98 97 [2] 9a 96 [2] 81 90 [2] 9d 97 [2] 81 b8 }

  condition:
    any of them
}