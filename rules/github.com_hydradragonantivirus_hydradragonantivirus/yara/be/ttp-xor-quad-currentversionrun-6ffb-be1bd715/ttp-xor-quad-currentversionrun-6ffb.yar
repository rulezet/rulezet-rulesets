rule TTP_XOR_QUAD_CurrentVersionRun_6ffb {
  strings:
    $key_6ffb = { 3c 94 [2] 18 9a [2] 33 b6 [2] 1d 94 [2] 09 8f [2] 06 95 [2] 18 88 [2] 1a 89 [2] 01 8f [2] 1d 88 [2] 01 a7 }

  condition:
    any of them
}