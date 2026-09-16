rule TTP_XOR_QUAD_CurrentVersionRun_e33a {
  strings:
    $key_e33a = { b0 55 [2] 94 5b [2] bf 77 [2] 91 55 [2] 85 4e [2] 8a 54 [2] 94 49 [2] 96 48 [2] 8d 4e [2] 91 49 [2] 8d 66 }

  condition:
    any of them
}