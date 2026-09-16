rule TTP_XOR_QUAD_CurrentVersionRun_f82a {
  strings:
    $key_f82a = { ab 45 [2] 8f 4b [2] a4 67 [2] 8a 45 [2] 9e 5e [2] 91 44 [2] 8f 59 [2] 8d 58 [2] 96 5e [2] 8a 59 [2] 96 76 }

  condition:
    any of them
}