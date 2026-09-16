rule TTP_XOR_QUAD_CurrentVersionRun_394c {
  strings:
    $key_394c = { 6a 23 [2] 4e 2d [2] 65 01 [2] 4b 23 [2] 5f 38 [2] 50 22 [2] 4e 3f [2] 4c 3e [2] 57 38 [2] 4b 3f [2] 57 10 }

  condition:
    any of them
}