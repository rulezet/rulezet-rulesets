rule TTP_XOR_QUAD_CurrentVersionRun_575c {
  strings:
    $key_575c = { 04 33 [2] 20 3d [2] 0b 11 [2] 25 33 [2] 31 28 [2] 3e 32 [2] 20 2f [2] 22 2e [2] 39 28 [2] 25 2f [2] 39 00 }

  condition:
    any of them
}