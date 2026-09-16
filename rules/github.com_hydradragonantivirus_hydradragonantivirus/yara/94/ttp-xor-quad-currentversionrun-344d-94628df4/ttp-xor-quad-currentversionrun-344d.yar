rule TTP_XOR_QUAD_CurrentVersionRun_344d {
  strings:
    $key_344d = { 67 22 [2] 43 2c [2] 68 00 [2] 46 22 [2] 52 39 [2] 5d 23 [2] 43 3e [2] 41 3f [2] 5a 39 [2] 46 3e [2] 5a 11 }

  condition:
    any of them
}