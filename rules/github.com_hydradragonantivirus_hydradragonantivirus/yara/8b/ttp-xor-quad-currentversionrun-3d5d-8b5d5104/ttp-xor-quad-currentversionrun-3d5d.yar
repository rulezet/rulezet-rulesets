rule TTP_XOR_QUAD_CurrentVersionRun_3d5d {
  strings:
    $key_3d5d = { 6e 32 [2] 4a 3c [2] 61 10 [2] 4f 32 [2] 5b 29 [2] 54 33 [2] 4a 2e [2] 48 2f [2] 53 29 [2] 4f 2e [2] 53 01 }

  condition:
    any of them
}