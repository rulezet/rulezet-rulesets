rule TTP_XOR_QUAD_CurrentVersionRun_1eff {
  strings:
    $key_1eff = { 4d 90 [2] 69 9e [2] 42 b2 [2] 6c 90 [2] 78 8b [2] 77 91 [2] 69 8c [2] 6b 8d [2] 70 8b [2] 6c 8c [2] 70 a3 }

  condition:
    any of them
}