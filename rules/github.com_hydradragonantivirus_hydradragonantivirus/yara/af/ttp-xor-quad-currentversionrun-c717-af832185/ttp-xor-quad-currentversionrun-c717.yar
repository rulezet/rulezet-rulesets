rule TTP_XOR_QUAD_CurrentVersionRun_c717 {
  strings:
    $key_c717 = { 94 78 [2] b0 76 [2] 9b 5a [2] b5 78 [2] a1 63 [2] ae 79 [2] b0 64 [2] b2 65 [2] a9 63 [2] b5 64 [2] a9 4b }

  condition:
    any of them
}