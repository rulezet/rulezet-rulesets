rule TTP_XOR_QUAD_CurrentVersionRun_effc {
  strings:
    $key_effc = { bc 93 [2] 98 9d [2] b3 b1 [2] 9d 93 [2] 89 88 [2] 86 92 [2] 98 8f [2] 9a 8e [2] 81 88 [2] 9d 8f [2] 81 a0 }

  condition:
    any of them
}