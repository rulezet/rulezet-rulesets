rule TTP_XOR_QUAD_CurrentVersionRun_792d {
  strings:
    $key_792d = { 2a 42 [2] 0e 4c [2] 25 60 [2] 0b 42 [2] 1f 59 [2] 10 43 [2] 0e 5e [2] 0c 5f [2] 17 59 [2] 0b 5e [2] 17 71 }

  condition:
    any of them
}