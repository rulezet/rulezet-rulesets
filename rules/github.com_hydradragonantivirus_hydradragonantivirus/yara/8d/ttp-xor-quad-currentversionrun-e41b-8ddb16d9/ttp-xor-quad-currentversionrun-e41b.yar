rule TTP_XOR_QUAD_CurrentVersionRun_e41b {
  strings:
    $key_e41b = { b7 74 [2] 93 7a [2] b8 56 [2] 96 74 [2] 82 6f [2] 8d 75 [2] 93 68 [2] 91 69 [2] 8a 6f [2] 96 68 [2] 8a 47 }

  condition:
    any of them
}