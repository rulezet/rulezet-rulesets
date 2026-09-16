rule TTP_XOR_QUAD_CurrentVersionRun_e43b {
  strings:
    $key_e43b = { b7 54 [2] 93 5a [2] b8 76 [2] 96 54 [2] 82 4f [2] 8d 55 [2] 93 48 [2] 91 49 [2] 8a 4f [2] 96 48 [2] 8a 67 }

  condition:
    any of them
}