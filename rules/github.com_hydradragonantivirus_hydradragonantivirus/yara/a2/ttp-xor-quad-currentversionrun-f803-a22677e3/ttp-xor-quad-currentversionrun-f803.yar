rule TTP_XOR_QUAD_CurrentVersionRun_f803 {
  strings:
    $key_f803 = { ab 6c [2] 8f 62 [2] a4 4e [2] 8a 6c [2] 9e 77 [2] 91 6d [2] 8f 70 [2] 8d 71 [2] 96 77 [2] 8a 70 [2] 96 5f }

  condition:
    any of them
}