rule TTP_XOR_QUAD_CurrentVersionRun_f60f {
  strings:
    $key_f60f = { a5 60 [2] 81 6e [2] aa 42 [2] 84 60 [2] 90 7b [2] 9f 61 [2] 81 7c [2] 83 7d [2] 98 7b [2] 84 7c [2] 98 53 }

  condition:
    any of them
}