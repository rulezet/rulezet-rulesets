rule TTP_XOR_QUAD_CurrentVersionRun_e44b {
  strings:
    $key_e44b = { b7 24 [2] 93 2a [2] b8 06 [2] 96 24 [2] 82 3f [2] 8d 25 [2] 93 38 [2] 91 39 [2] 8a 3f [2] 96 38 [2] 8a 17 }

  condition:
    any of them
}