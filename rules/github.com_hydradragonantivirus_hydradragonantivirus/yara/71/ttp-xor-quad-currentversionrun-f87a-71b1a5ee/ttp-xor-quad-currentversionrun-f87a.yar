rule TTP_XOR_QUAD_CurrentVersionRun_f87a {
  strings:
    $key_f87a = { ab 15 [2] 8f 1b [2] a4 37 [2] 8a 15 [2] 9e 0e [2] 91 14 [2] 8f 09 [2] 8d 08 [2] 96 0e [2] 8a 09 [2] 96 26 }

  condition:
    any of them
}