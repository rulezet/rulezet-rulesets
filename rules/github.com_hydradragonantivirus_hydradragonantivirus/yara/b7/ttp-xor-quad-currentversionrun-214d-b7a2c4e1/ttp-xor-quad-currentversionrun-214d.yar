rule TTP_XOR_QUAD_CurrentVersionRun_214d {
  strings:
    $key_214d = { 72 22 [2] 56 2c [2] 7d 00 [2] 53 22 [2] 47 39 [2] 48 23 [2] 56 3e [2] 54 3f [2] 4f 39 [2] 53 3e [2] 4f 11 }

  condition:
    any of them
}