rule TTP_XOR_QUAD_CurrentVersionRun_4cfb {
  strings:
    $key_4cfb = { 1f 94 [2] 3b 9a [2] 10 b6 [2] 3e 94 [2] 2a 8f [2] 25 95 [2] 3b 88 [2] 39 89 [2] 22 8f [2] 3e 88 [2] 22 a7 }

  condition:
    any of them
}