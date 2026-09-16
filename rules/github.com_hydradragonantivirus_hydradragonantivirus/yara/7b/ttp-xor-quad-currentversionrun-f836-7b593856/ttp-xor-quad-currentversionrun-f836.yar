rule TTP_XOR_QUAD_CurrentVersionRun_f836 {
  strings:
    $key_f836 = { ab 59 [2] 8f 57 [2] a4 7b [2] 8a 59 [2] 9e 42 [2] 91 58 [2] 8f 45 [2] 8d 44 [2] 96 42 [2] 8a 45 [2] 96 6a }

  condition:
    any of them
}