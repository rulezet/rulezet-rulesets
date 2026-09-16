rule TTP_XOR_QUAD_CurrentVersionRun_c032 {
  strings:
    $key_c032 = { 93 5d [2] b7 53 [2] 9c 7f [2] b2 5d [2] a6 46 [2] a9 5c [2] b7 41 [2] b5 40 [2] ae 46 [2] b2 41 [2] ae 6e }

  condition:
    any of them
}