rule TTP_XOR_QUAD_CurrentVersionRun_c7f2 {
  strings:
    $key_c7f2 = { 94 9d [2] b0 93 [2] 9b bf [2] b5 9d [2] a1 86 [2] ae 9c [2] b0 81 [2] b2 80 [2] a9 86 [2] b5 81 [2] a9 ae }

  condition:
    any of them
}