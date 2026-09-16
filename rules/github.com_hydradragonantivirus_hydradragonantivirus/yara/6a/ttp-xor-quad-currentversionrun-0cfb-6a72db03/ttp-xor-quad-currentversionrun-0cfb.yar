rule TTP_XOR_QUAD_CurrentVersionRun_0cfb {
  strings:
    $key_0cfb = { 5f 94 [2] 7b 9a [2] 50 b6 [2] 7e 94 [2] 6a 8f [2] 65 95 [2] 7b 88 [2] 79 89 [2] 62 8f [2] 7e 88 [2] 62 a7 }

  condition:
    any of them
}