rule TTP_XOR_QUAD_CurrentVersionRun_f80a {
  strings:
    $key_f80a = { ab 65 [2] 8f 6b [2] a4 47 [2] 8a 65 [2] 9e 7e [2] 91 64 [2] 8f 79 [2] 8d 78 [2] 96 7e [2] 8a 79 [2] 96 56 }

  condition:
    any of them
}