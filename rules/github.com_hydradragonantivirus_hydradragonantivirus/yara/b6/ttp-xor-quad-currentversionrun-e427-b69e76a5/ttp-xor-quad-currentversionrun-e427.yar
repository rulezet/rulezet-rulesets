rule TTP_XOR_QUAD_CurrentVersionRun_e427 {
  strings:
    $key_e427 = { b7 48 [2] 93 46 [2] b8 6a [2] 96 48 [2] 82 53 [2] 8d 49 [2] 93 54 [2] 91 55 [2] 8a 53 [2] 96 54 [2] 8a 7b }

  condition:
    any of them
}