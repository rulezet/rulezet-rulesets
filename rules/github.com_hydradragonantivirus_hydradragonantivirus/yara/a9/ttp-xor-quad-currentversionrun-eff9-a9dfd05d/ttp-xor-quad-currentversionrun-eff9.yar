rule TTP_XOR_QUAD_CurrentVersionRun_eff9 {
  strings:
    $key_eff9 = { bc 96 [2] 98 98 [2] b3 b4 [2] 9d 96 [2] 89 8d [2] 86 97 [2] 98 8a [2] 9a 8b [2] 81 8d [2] 9d 8a [2] 81 a5 }

  condition:
    any of them
}