rule TTP_XOR_QUAD_CurrentVersionRun_f824 {
  strings:
    $key_f824 = { ab 4b [2] 8f 45 [2] a4 69 [2] 8a 4b [2] 9e 50 [2] 91 4a [2] 8f 57 [2] 8d 56 [2] 96 50 [2] 8a 57 [2] 96 78 }

  condition:
    any of them
}