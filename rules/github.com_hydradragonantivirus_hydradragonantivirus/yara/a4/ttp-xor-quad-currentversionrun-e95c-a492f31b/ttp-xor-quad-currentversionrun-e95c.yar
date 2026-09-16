rule TTP_XOR_QUAD_CurrentVersionRun_e95c {
  strings:
    $key_e95c = { ba 33 [2] 9e 3d [2] b5 11 [2] 9b 33 [2] 8f 28 [2] 80 32 [2] 9e 2f [2] 9c 2e [2] 87 28 [2] 9b 2f [2] 87 00 }

  condition:
    any of them
}