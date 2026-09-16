rule TTP_XOR_QUAD_CurrentVersionRun_545d {
  strings:
    $key_545d = { 07 32 [2] 23 3c [2] 08 10 [2] 26 32 [2] 32 29 [2] 3d 33 [2] 23 2e [2] 21 2f [2] 3a 29 [2] 26 2e [2] 3a 01 }

  condition:
    any of them
}