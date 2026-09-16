rule TTP_XOR_QUAD_CurrentVersionRun_6cfb {
  strings:
    $key_6cfb = { 3f 94 [2] 1b 9a [2] 30 b6 [2] 1e 94 [2] 0a 8f [2] 05 95 [2] 1b 88 [2] 19 89 [2] 02 8f [2] 1e 88 [2] 02 a7 }

  condition:
    any of them
}