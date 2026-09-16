rule TTP_XOR_QUAD_CurrentVersionRun_f60e {
  strings:
    $key_f60e = { a5 61 [2] 81 6f [2] aa 43 [2] 84 61 [2] 90 7a [2] 9f 60 [2] 81 7d [2] 83 7c [2] 98 7a [2] 84 7d [2] 98 52 }

  condition:
    any of them
}