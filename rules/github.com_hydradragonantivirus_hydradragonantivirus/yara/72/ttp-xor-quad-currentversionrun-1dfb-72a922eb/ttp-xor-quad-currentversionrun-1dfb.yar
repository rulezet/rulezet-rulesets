rule TTP_XOR_QUAD_CurrentVersionRun_1dfb {
  strings:
    $key_1dfb = { 4e 94 [2] 6a 9a [2] 41 b6 [2] 6f 94 [2] 7b 8f [2] 74 95 [2] 6a 88 [2] 68 89 [2] 73 8f [2] 6f 88 [2] 73 a7 }

  condition:
    any of them
}