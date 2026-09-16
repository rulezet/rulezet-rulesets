rule TTP_XOR_QUAD_CurrentVersionRun_f833 {
  strings:
    $key_f833 = { ab 5c [2] 8f 52 [2] a4 7e [2] 8a 5c [2] 9e 47 [2] 91 5d [2] 8f 40 [2] 8d 41 [2] 96 47 [2] 8a 40 [2] 96 6f }

  condition:
    any of them
}