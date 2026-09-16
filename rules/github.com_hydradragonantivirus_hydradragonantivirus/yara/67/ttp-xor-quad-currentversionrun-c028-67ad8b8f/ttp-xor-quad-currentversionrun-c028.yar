rule TTP_XOR_QUAD_CurrentVersionRun_c028 {
  strings:
    $key_c028 = { 93 47 [2] b7 49 [2] 9c 65 [2] b2 47 [2] a6 5c [2] a9 46 [2] b7 5b [2] b5 5a [2] ae 5c [2] b2 5b [2] ae 74 }

  condition:
    any of them
}