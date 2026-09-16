rule TTP_XOR_QUAD_CurrentVersionRun_305c {
  strings:
    $key_305c = { 63 33 [2] 47 3d [2] 6c 11 [2] 42 33 [2] 56 28 [2] 59 32 [2] 47 2f [2] 45 2e [2] 5e 28 [2] 42 2f [2] 5e 00 }

  condition:
    any of them
}