rule TTP_XOR_QUAD_CurrentVersionRun_40ef {
  strings:
    $key_40ef = { 13 80 [2] 37 8e [2] 1c a2 [2] 32 80 [2] 26 9b [2] 29 81 [2] 37 9c [2] 35 9d [2] 2e 9b [2] 32 9c [2] 2e b3 }

  condition:
    any of them
}