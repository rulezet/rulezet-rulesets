rule TTP_XOR_QUAD_CurrentVersionRun_f82d {
  strings:
    $key_f82d = { ab 42 [2] 8f 4c [2] a4 60 [2] 8a 42 [2] 9e 59 [2] 91 43 [2] 8f 5e [2] 8d 5f [2] 96 59 [2] 8a 5e [2] 96 71 }

  condition:
    any of them
}