rule TTP_XOR_QUAD_CurrentVersionRun_f827 {
  strings:
    $key_f827 = { ab 48 [2] 8f 46 [2] a4 6a [2] 8a 48 [2] 9e 53 [2] 91 49 [2] 8f 54 [2] 8d 55 [2] 96 53 [2] 8a 54 [2] 96 7b }

  condition:
    any of them
}