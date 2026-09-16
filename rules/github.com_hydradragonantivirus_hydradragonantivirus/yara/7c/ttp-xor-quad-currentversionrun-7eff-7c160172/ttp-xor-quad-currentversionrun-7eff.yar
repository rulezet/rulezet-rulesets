rule TTP_XOR_QUAD_CurrentVersionRun_7eff {
  strings:
    $key_7eff = { 2d 90 [2] 09 9e [2] 22 b2 [2] 0c 90 [2] 18 8b [2] 17 91 [2] 09 8c [2] 0b 8d [2] 10 8b [2] 0c 8c [2] 10 a3 }

  condition:
    any of them
}