rule TTP_XOR_QUAD_CurrentVersionRun_294c {
  strings:
    $key_294c = { 7a 23 [2] 5e 2d [2] 75 01 [2] 5b 23 [2] 4f 38 [2] 40 22 [2] 5e 3f [2] 5c 3e [2] 47 38 [2] 5b 3f [2] 47 10 }

  condition:
    any of them
}