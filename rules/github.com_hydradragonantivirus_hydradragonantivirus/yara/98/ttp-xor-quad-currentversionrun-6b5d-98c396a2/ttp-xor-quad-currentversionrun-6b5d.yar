rule TTP_XOR_QUAD_CurrentVersionRun_6b5d {
  strings:
    $key_6b5d = { 38 32 [2] 1c 3c [2] 37 10 [2] 19 32 [2] 0d 29 [2] 02 33 [2] 1c 2e [2] 1e 2f [2] 05 29 [2] 19 2e [2] 05 01 }

  condition:
    any of them
}