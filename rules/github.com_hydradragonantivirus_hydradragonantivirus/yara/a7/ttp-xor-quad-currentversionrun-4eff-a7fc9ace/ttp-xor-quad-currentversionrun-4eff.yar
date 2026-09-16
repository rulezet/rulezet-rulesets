rule TTP_XOR_QUAD_CurrentVersionRun_4eff {
  strings:
    $key_4eff = { 1d 90 [2] 39 9e [2] 12 b2 [2] 3c 90 [2] 28 8b [2] 27 91 [2] 39 8c [2] 3b 8d [2] 20 8b [2] 3c 8c [2] 20 a3 }

  condition:
    any of them
}