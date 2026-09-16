rule TTP_XOR_QUAD_CurrentVersionRun_e405 {
  strings:
    $key_e405 = { b7 6a [2] 93 64 [2] b8 48 [2] 96 6a [2] 82 71 [2] 8d 6b [2] 93 76 [2] 91 77 [2] 8a 71 [2] 96 76 [2] 8a 59 }

  condition:
    any of them
}