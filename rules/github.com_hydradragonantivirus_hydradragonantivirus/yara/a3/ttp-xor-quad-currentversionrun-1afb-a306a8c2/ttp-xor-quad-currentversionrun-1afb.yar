rule TTP_XOR_QUAD_CurrentVersionRun_1afb {
  strings:
    $key_1afb = { 49 94 [2] 6d 9a [2] 46 b6 [2] 68 94 [2] 7c 8f [2] 73 95 [2] 6d 88 [2] 6f 89 [2] 74 8f [2] 68 88 [2] 74 a7 }

  condition:
    any of them
}