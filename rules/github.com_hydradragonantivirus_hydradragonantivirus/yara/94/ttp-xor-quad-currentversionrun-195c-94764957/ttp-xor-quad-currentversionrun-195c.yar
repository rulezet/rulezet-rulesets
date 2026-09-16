rule TTP_XOR_QUAD_CurrentVersionRun_195c {
  strings:
    $key_195c = { 4a 33 [2] 6e 3d [2] 45 11 [2] 6b 33 [2] 7f 28 [2] 70 32 [2] 6e 2f [2] 6c 2e [2] 77 28 [2] 6b 2f [2] 77 00 }

  condition:
    any of them
}