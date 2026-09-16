rule TTP_XOR_QUAD_CurrentVersionRun_f86a {
  strings:
    $key_f86a = { ab 05 [2] 8f 0b [2] a4 27 [2] 8a 05 [2] 9e 1e [2] 91 04 [2] 8f 19 [2] 8d 18 [2] 96 1e [2] 8a 19 [2] 96 36 }

  condition:
    any of them
}