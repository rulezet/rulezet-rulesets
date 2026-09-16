rule TTP_XOR_QUAD_CurrentVersionRun_68ff {
  strings:
    $key_68ff = { 3b 90 [2] 1f 9e [2] 34 b2 [2] 1a 90 [2] 0e 8b [2] 01 91 [2] 1f 8c [2] 1d 8d [2] 06 8b [2] 1a 8c [2] 06 a3 }

  condition:
    any of them
}