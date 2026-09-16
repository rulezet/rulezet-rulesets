rule TTP_XOR_QUAD_CurrentVersionRun_695c {
  strings:
    $key_695c = { 3a 33 [2] 1e 3d [2] 35 11 [2] 1b 33 [2] 0f 28 [2] 00 32 [2] 1e 2f [2] 1c 2e [2] 07 28 [2] 1b 2f [2] 07 00 }

  condition:
    any of them
}