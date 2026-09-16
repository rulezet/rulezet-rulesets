rule TTP_XOR_QUAD_CurrentVersionRun_314d {
  strings:
    $key_314d = { 62 22 [2] 46 2c [2] 6d 00 [2] 43 22 [2] 57 39 [2] 58 23 [2] 46 3e [2] 44 3f [2] 5f 39 [2] 43 3e [2] 5f 11 }

  condition:
    any of them
}