rule TTP_XOR_QUAD_CurrentVersionRun_6dfb {
  strings:
    $key_6dfb = { 3e 94 [2] 1a 9a [2] 31 b6 [2] 1f 94 [2] 0b 8f [2] 04 95 [2] 1a 88 [2] 18 89 [2] 03 8f [2] 1f 88 [2] 03 a7 }

  condition:
    any of them
}