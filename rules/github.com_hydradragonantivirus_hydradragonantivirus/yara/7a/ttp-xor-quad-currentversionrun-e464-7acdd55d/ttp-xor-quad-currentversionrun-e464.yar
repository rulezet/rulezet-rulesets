rule TTP_XOR_QUAD_CurrentVersionRun_e464 {
  strings:
    $key_e464 = { b7 0b [2] 93 05 [2] b8 29 [2] 96 0b [2] 82 10 [2] 8d 0a [2] 93 17 [2] 91 16 [2] 8a 10 [2] 96 17 [2] 8a 38 }

  condition:
    any of them
}