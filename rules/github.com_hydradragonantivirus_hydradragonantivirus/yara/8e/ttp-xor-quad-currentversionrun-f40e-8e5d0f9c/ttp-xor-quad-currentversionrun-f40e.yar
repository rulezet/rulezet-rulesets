rule TTP_XOR_QUAD_CurrentVersionRun_f40e {
  strings:
    $key_f40e = { a7 61 [2] 83 6f [2] a8 43 [2] 86 61 [2] 92 7a [2] 9d 60 [2] 83 7d [2] 81 7c [2] 9a 7a [2] 86 7d [2] 9a 52 }

  condition:
    any of them
}