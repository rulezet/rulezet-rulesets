rule TTP_XOR_QUAD_CurrentVersionRun_e4e5 {
  strings:
    $key_e4e5 = { b7 8a [2] 93 84 [2] b8 a8 [2] 96 8a [2] 82 91 [2] 8d 8b [2] 93 96 [2] 91 97 [2] 8a 91 [2] 96 96 [2] 8a b9 }

  condition:
    any of them
}