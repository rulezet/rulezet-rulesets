rule TTP_XOR_QUAD_CurrentVersionRun_e425 {
  strings:
    $key_e425 = { b7 4a [2] 93 44 [2] b8 68 [2] 96 4a [2] 82 51 [2] 8d 4b [2] 93 56 [2] 91 57 [2] 8a 51 [2] 96 56 [2] 8a 79 }

  condition:
    any of them
}