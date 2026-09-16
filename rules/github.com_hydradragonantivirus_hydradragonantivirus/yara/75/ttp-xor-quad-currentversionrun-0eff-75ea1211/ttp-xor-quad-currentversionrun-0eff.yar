rule TTP_XOR_QUAD_CurrentVersionRun_0eff {
  strings:
    $key_0eff = { 5d 90 [2] 79 9e [2] 52 b2 [2] 7c 90 [2] 68 8b [2] 67 91 [2] 79 8c [2] 7b 8d [2] 60 8b [2] 7c 8c [2] 60 a3 }

  condition:
    any of them
}