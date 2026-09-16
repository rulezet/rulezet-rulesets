rule TTP_XOR_QUAD_CurrentVersionRun_effb {
  strings:
    $key_effb = { bc 94 [2] 98 9a [2] b3 b6 [2] 9d 94 [2] 89 8f [2] 86 95 [2] 98 88 [2] 9a 89 [2] 81 8f [2] 9d 88 [2] 81 a7 }

  condition:
    any of them
}