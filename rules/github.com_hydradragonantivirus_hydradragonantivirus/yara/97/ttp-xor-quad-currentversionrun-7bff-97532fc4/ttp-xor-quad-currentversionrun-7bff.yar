rule TTP_XOR_QUAD_CurrentVersionRun_7bff {
  strings:
    $key_7bff = { 28 90 [2] 0c 9e [2] 27 b2 [2] 09 90 [2] 1d 8b [2] 12 91 [2] 0c 8c [2] 0e 8d [2] 15 8b [2] 09 8c [2] 15 a3 }

  condition:
    any of them
}