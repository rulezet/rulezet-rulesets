rule TTP_XOR_QUAD_CurrentVersionRun_0efb {
  strings:
    $key_0efb = { 5d 94 [2] 79 9a [2] 52 b6 [2] 7c 94 [2] 68 8f [2] 67 95 [2] 79 88 [2] 7b 89 [2] 60 8f [2] 7c 88 [2] 60 a7 }

  condition:
    any of them
}