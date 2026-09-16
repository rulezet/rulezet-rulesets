rule TTP_XOR_QUAD_CurrentVersionRun_c0f2 {
  strings:
    $key_c0f2 = { 93 9d [2] b7 93 [2] 9c bf [2] b2 9d [2] a6 86 [2] a9 9c [2] b7 81 [2] b5 80 [2] ae 86 [2] b2 81 [2] ae ae }

  condition:
    any of them
}