rule TTP_XOR_QUAD_CurrentVersionRun_324c {
  strings:
    $key_324c = { 61 23 [2] 45 2d [2] 6e 01 [2] 40 23 [2] 54 38 [2] 5b 22 [2] 45 3f [2] 47 3e [2] 5c 38 [2] 40 3f [2] 5c 10 }

  condition:
    any of them
}