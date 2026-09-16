rule TTP_XOR_QUAD_CurrentVersionRun_f84a {
  strings:
    $key_f84a = { ab 25 [2] 8f 2b [2] a4 07 [2] 8a 25 [2] 9e 3e [2] 91 24 [2] 8f 39 [2] 8d 38 [2] 96 3e [2] 8a 39 [2] 96 16 }

  condition:
    any of them
}