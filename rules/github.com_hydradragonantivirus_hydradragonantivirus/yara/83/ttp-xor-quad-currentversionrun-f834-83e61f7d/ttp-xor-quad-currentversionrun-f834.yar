rule TTP_XOR_QUAD_CurrentVersionRun_f834 {
  strings:
    $key_f834 = { ab 5b [2] 8f 55 [2] a4 79 [2] 8a 5b [2] 9e 40 [2] 91 5a [2] 8f 47 [2] 8d 46 [2] 96 40 [2] 8a 47 [2] 96 68 }

  condition:
    any of them
}