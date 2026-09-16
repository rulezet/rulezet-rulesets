rule TTP_XOR_QUAD_CurrentVersionRun_3cff {
  strings:
    $key_3cff = { 6f 90 [2] 4b 9e [2] 60 b2 [2] 4e 90 [2] 5a 8b [2] 55 91 [2] 4b 8c [2] 49 8d [2] 52 8b [2] 4e 8c [2] 52 a3 }

  condition:
    any of them
}