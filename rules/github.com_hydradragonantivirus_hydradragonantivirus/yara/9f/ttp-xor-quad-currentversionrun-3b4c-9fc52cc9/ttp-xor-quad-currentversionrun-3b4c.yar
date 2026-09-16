rule TTP_XOR_QUAD_CurrentVersionRun_3b4c {
  strings:
    $key_3b4c = { 68 23 [2] 4c 2d [2] 67 01 [2] 49 23 [2] 5d 38 [2] 52 22 [2] 4c 3f [2] 4e 3e [2] 55 38 [2] 49 3f [2] 55 10 }

  condition:
    any of them
}