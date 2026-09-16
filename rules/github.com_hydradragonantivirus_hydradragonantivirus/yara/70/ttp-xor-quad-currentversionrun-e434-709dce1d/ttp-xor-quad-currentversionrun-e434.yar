rule TTP_XOR_QUAD_CurrentVersionRun_e434 {
  strings:
    $key_e434 = { b7 5b [2] 93 55 [2] b8 79 [2] 96 5b [2] 82 40 [2] 8d 5a [2] 93 47 [2] 91 46 [2] 8a 40 [2] 96 47 [2] 8a 68 }

  condition:
    any of them
}