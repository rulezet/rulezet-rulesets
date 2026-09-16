rule TTP_XOR_QUAD_CurrentVersionRun_2e4c {
  strings:
    $key_2e4c = { 7d 23 [2] 59 2d [2] 72 01 [2] 5c 23 [2] 48 38 [2] 47 22 [2] 59 3f [2] 5b 3e [2] 40 38 [2] 5c 3f [2] 40 10 }

  condition:
    any of them
}