rule TTP_XOR_QUAD_CurrentVersionRun_005d {
  strings:
    $key_005d = { 53 32 [2] 77 3c [2] 5c 10 [2] 72 32 [2] 66 29 [2] 69 33 [2] 77 2e [2] 75 2f [2] 6e 29 [2] 72 2e [2] 6e 01 }

  condition:
    any of them
}