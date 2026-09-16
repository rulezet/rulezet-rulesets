rule TTP_XOR_QUAD_CurrentVersionRun_ef33 {
  strings:
    $key_ef33 = { bc 5c [2] 98 52 [2] b3 7e [2] 9d 5c [2] 89 47 [2] 86 5d [2] 98 40 [2] 9a 41 [2] 81 47 [2] 9d 40 [2] 81 6f }

  condition:
    any of them
}