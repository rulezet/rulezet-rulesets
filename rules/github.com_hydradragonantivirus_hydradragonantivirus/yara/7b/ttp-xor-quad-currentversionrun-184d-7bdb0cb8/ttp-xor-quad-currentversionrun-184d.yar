rule TTP_XOR_QUAD_CurrentVersionRun_184d {
  strings:
    $key_184d = { 4b 22 [2] 6f 2c [2] 44 00 [2] 6a 22 [2] 7e 39 [2] 71 23 [2] 6f 3e [2] 6d 3f [2] 76 39 [2] 6a 3e [2] 76 11 }

  condition:
    any of them
}