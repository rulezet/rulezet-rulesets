rule TTP_XOR_QUAD_CurrentVersionRun_e325 {
  strings:
    $key_e325 = { b0 4a [2] 94 44 [2] bf 68 [2] 91 4a [2] 85 51 [2] 8a 4b [2] 94 56 [2] 96 57 [2] 8d 51 [2] 91 56 [2] 8d 79 }

  condition:
    any of them
}