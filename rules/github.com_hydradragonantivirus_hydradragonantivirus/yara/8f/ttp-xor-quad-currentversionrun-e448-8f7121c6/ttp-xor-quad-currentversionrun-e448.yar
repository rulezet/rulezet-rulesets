rule TTP_XOR_QUAD_CurrentVersionRun_e448 {
  strings:
    $key_e448 = { b7 27 [2] 93 29 [2] b8 05 [2] 96 27 [2] 82 3c [2] 8d 26 [2] 93 3b [2] 91 3a [2] 8a 3c [2] 96 3b [2] 8a 14 }

  condition:
    any of them
}