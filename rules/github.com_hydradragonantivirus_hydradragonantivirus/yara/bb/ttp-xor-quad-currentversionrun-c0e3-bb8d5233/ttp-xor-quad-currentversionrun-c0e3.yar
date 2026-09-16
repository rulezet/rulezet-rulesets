rule TTP_XOR_QUAD_CurrentVersionRun_c0e3 {
  strings:
    $key_c0e3 = { 93 8c [2] b7 82 [2] 9c ae [2] b2 8c [2] a6 97 [2] a9 8d [2] b7 90 [2] b5 91 [2] ae 97 [2] b2 90 [2] ae bf }

  condition:
    any of them
}