rule TTP_XOR_QUAD_CurrentVersionRun_3eff {
  strings:
    $key_3eff = { 6d 90 [2] 49 9e [2] 62 b2 [2] 4c 90 [2] 58 8b [2] 57 91 [2] 49 8c [2] 4b 8d [2] 50 8b [2] 4c 8c [2] 50 a3 }

  condition:
    any of them
}