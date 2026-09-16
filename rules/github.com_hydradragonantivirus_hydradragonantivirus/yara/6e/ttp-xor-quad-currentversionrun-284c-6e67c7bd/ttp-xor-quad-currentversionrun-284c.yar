rule TTP_XOR_QUAD_CurrentVersionRun_284c {
  strings:
    $key_284c = { 7b 23 [2] 5f 2d [2] 74 01 [2] 5a 23 [2] 4e 38 [2] 41 22 [2] 5f 3f [2] 5d 3e [2] 46 38 [2] 5a 3f [2] 46 10 }

  condition:
    any of them
}