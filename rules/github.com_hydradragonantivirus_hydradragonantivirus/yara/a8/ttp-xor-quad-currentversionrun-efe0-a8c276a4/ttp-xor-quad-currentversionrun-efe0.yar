rule TTP_XOR_QUAD_CurrentVersionRun_efe0 {
  strings:
    $key_efe0 = { bc 8f [2] 98 81 [2] b3 ad [2] 9d 8f [2] 89 94 [2] 86 8e [2] 98 93 [2] 9a 92 [2] 81 94 [2] 9d 93 [2] 81 bc }

  condition:
    any of them
}