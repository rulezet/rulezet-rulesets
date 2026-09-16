rule TTP_XOR_QUAD_CurrentVersionRun_335d {
  strings:
    $key_335d = { 60 32 [2] 44 3c [2] 6f 10 [2] 41 32 [2] 55 29 [2] 5a 33 [2] 44 2e [2] 46 2f [2] 5d 29 [2] 41 2e [2] 5d 01 }

  condition:
    any of them
}