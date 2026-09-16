rule TTP_XOR_QUAD_CurrentVersionRun_f87c {
  strings:
    $key_f87c = { ab 13 [2] 8f 1d [2] a4 31 [2] 8a 13 [2] 9e 08 [2] 91 12 [2] 8f 0f [2] 8d 0e [2] 96 08 [2] 8a 0f [2] 96 20 }

  condition:
    any of them
}