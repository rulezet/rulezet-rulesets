rule TTP_XOR_QUAD_CurrentVersionRun_665c {
  strings:
    $key_665c = { 35 33 [2] 11 3d [2] 3a 11 [2] 14 33 [2] 00 28 [2] 0f 32 [2] 11 2f [2] 13 2e [2] 08 28 [2] 14 2f [2] 08 00 }

  condition:
    any of them
}