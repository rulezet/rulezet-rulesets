rule TTP_XOR_QUAD_CurrentVersionRun_794c {
  strings:
    $key_794c = { 2a 23 [2] 0e 2d [2] 25 01 [2] 0b 23 [2] 1f 38 [2] 10 22 [2] 0e 3f [2] 0c 3e [2] 17 38 [2] 0b 3f [2] 17 10 }

  condition:
    any of them
}