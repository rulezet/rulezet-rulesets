rule TTP_XOR_QUAD_CurrentVersionRun_3dfb {
  strings:
    $key_3dfb = { 6e 94 [2] 4a 9a [2] 61 b6 [2] 4f 94 [2] 5b 8f [2] 54 95 [2] 4a 88 [2] 48 89 [2] 53 8f [2] 4f 88 [2] 53 a7 }

  condition:
    any of them
}