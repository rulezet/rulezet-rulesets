rule TTP_XOR_QUAD_CurrentVersionRun_ef7f {
  strings:
    $key_ef7f = { bc 10 [2] 98 1e [2] b3 32 [2] 9d 10 [2] 89 0b [2] 86 11 [2] 98 0c [2] 9a 0d [2] 81 0b [2] 9d 0c [2] 81 23 }

  condition:
    any of them
}