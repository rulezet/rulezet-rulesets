rule TTP_XOR_QUAD_CurrentVersionRun_e4fe {
  strings:
    $key_e4fe = { b7 91 [2] 93 9f [2] b8 b3 [2] 96 91 [2] 82 8a [2] 8d 90 [2] 93 8d [2] 91 8c [2] 8a 8a [2] 96 8d [2] 8a a2 }

  condition:
    any of them
}