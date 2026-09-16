rule TTP_XOR_QUAD_CurrentVersionRun_efff {
  strings:
    $key_efff = { bc 90 [2] 98 9e [2] b3 b2 [2] 9d 90 [2] 89 8b [2] 86 91 [2] 98 8c [2] 9a 8d [2] 81 8b [2] 9d 8c [2] 81 a3 }

  condition:
    any of them
}