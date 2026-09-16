rule TTP_XOR_QUAD_CurrentVersionRun_7efb {
  strings:
    $key_7efb = { 2d 94 [2] 09 9a [2] 22 b6 [2] 0c 94 [2] 18 8f [2] 17 95 [2] 09 88 [2] 0b 89 [2] 10 8f [2] 0c 88 [2] 10 a7 }

  condition:
    any of them
}