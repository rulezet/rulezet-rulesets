rule TTP_XOR_QUAD_CurrentVersionRun_f87b {
  strings:
    $key_f87b = { ab 14 [2] 8f 1a [2] a4 36 [2] 8a 14 [2] 9e 0f [2] 91 15 [2] 8f 08 [2] 8d 09 [2] 96 0f [2] 8a 08 [2] 96 27 }

  condition:
    any of them
}