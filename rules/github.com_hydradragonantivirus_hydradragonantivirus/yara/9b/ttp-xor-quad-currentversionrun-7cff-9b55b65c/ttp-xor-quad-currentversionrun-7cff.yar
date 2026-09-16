rule TTP_XOR_QUAD_CurrentVersionRun_7cff {
  strings:
    $key_7cff = { 2f 90 [2] 0b 9e [2] 20 b2 [2] 0e 90 [2] 1a 8b [2] 15 91 [2] 0b 8c [2] 09 8d [2] 12 8b [2] 0e 8c [2] 12 a3 }

  condition:
    any of them
}