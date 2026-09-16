rule TTP_XOR_QUAD_CurrentVersionRun_2bff {
  strings:
    $key_2bff = { 78 90 [2] 5c 9e [2] 77 b2 [2] 59 90 [2] 4d 8b [2] 42 91 [2] 5c 8c [2] 5e 8d [2] 45 8b [2] 59 8c [2] 45 a3 }

  condition:
    any of them
}