rule TTP_XOR_QUAD_CurrentVersionRun_efe8 {
  strings:
    $key_efe8 = { bc 87 [2] 98 89 [2] b3 a5 [2] 9d 87 [2] 89 9c [2] 86 86 [2] 98 9b [2] 9a 9a [2] 81 9c [2] 9d 9b [2] 81 b4 }

  condition:
    any of them
}