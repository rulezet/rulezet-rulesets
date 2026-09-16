rule TTP_XOR_QUAD_CurrentVersionRun_f854 {
  strings:
    $key_f854 = { ab 3b [2] 8f 35 [2] a4 19 [2] 8a 3b [2] 9e 20 [2] 91 3a [2] 8f 27 [2] 8d 26 [2] 96 20 [2] 8a 27 [2] 96 08 }

  condition:
    any of them
}