rule TTP_XOR_QUAD_CurrentVersionRun_2b4c {
  strings:
    $key_2b4c = { 78 23 [2] 5c 2d [2] 77 01 [2] 59 23 [2] 4d 38 [2] 42 22 [2] 5c 3f [2] 5e 3e [2] 45 38 [2] 59 3f [2] 45 10 }

  condition:
    any of them
}