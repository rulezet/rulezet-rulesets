rule TTP_XOR_QUAD_CurrentVersionRun_f60a {
  strings:
    $key_f60a = { a5 65 [2] 81 6b [2] aa 47 [2] 84 65 [2] 90 7e [2] 9f 64 [2] 81 79 [2] 83 78 [2] 98 7e [2] 84 79 [2] 98 56 }

  condition:
    any of them
}