rule TTP_XOR_QUAD_CurrentVersionRun_e46b {
  strings:
    $key_e46b = { b7 04 [2] 93 0a [2] b8 26 [2] 96 04 [2] 82 1f [2] 8d 05 [2] 93 18 [2] 91 19 [2] 8a 1f [2] 96 18 [2] 8a 37 }

  condition:
    any of them
}