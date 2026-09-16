rule TTP_XOR_QUAD_CurrentVersionRun_ddfb {
  strings:
    $key_ddfb = { 8e 94 [2] aa 9a [2] 81 b6 [2] af 94 [2] bb 8f [2] b4 95 [2] aa 88 [2] a8 89 [2] b3 8f [2] af 88 [2] b3 a7 }

  condition:
    any of them
}