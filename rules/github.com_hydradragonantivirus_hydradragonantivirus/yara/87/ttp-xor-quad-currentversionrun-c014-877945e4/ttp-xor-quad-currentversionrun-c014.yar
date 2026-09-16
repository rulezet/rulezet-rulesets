rule TTP_XOR_QUAD_CurrentVersionRun_c014 {
  strings:
    $key_c014 = { 93 7b [2] b7 75 [2] 9c 59 [2] b2 7b [2] a6 60 [2] a9 7a [2] b7 67 [2] b5 66 [2] ae 60 [2] b2 67 [2] ae 48 }

  condition:
    any of them
}