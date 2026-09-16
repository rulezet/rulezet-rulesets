rule TTP_XOR_QUAD_CurrentVersionRun_0f4d {
  strings:
    $key_0f4d = { 5c 22 [2] 78 2c [2] 53 00 [2] 7d 22 [2] 69 39 [2] 66 23 [2] 78 3e [2] 7a 3f [2] 61 39 [2] 7d 3e [2] 61 11 }

  condition:
    any of them
}