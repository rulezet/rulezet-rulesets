rule TTP_XOR_QUAD_CurrentVersionRun_c002 {
  strings:
    $key_c002 = { 93 6d [2] b7 63 [2] 9c 4f [2] b2 6d [2] a6 76 [2] a9 6c [2] b7 71 [2] b5 70 [2] ae 76 [2] b2 71 [2] ae 5e }

  condition:
    any of them
}