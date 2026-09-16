rule TTP_XOR_QUAD_CurrentVersionRun_3a5d {
  strings:
    $key_3a5d = { 69 32 [2] 4d 3c [2] 66 10 [2] 48 32 [2] 5c 29 [2] 53 33 [2] 4d 2e [2] 4f 2f [2] 54 29 [2] 48 2e [2] 54 01 }

  condition:
    any of them
}