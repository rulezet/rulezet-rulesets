rule TTP_XOR_QUAD_CurrentVersionRun_487d {
  strings:
    $key_487d = { 1b 12 [2] 3f 1c [2] 14 30 [2] 3a 12 [2] 2e 09 [2] 21 13 [2] 3f 0e [2] 3d 0f [2] 26 09 [2] 3a 0e [2] 26 21 }

  condition:
    any of them
}