rule TTP_XOR_QUAD_CurrentVersionRun_f86b {
  strings:
    $key_f86b = { ab 04 [2] 8f 0a [2] a4 26 [2] 8a 04 [2] 9e 1f [2] 91 05 [2] 8f 18 [2] 8d 19 [2] 96 1f [2] 8a 18 [2] 96 37 }

  condition:
    any of them
}