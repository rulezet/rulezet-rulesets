rule TTP_XOR_QUAD_CurrentVersionRun_5efb {
  strings:
    $key_5efb = { 0d 94 [2] 29 9a [2] 02 b6 [2] 2c 94 [2] 38 8f [2] 37 95 [2] 29 88 [2] 2b 89 [2] 30 8f [2] 2c 88 [2] 30 a7 }

  condition:
    any of them
}