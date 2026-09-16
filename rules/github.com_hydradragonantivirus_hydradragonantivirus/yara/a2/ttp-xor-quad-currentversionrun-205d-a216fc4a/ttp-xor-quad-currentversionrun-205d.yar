rule TTP_XOR_QUAD_CurrentVersionRun_205d {
  strings:
    $key_205d = { 73 32 [2] 57 3c [2] 7c 10 [2] 52 32 [2] 46 29 [2] 49 33 [2] 57 2e [2] 55 2f [2] 4e 29 [2] 52 2e [2] 4e 01 }

  condition:
    any of them
}