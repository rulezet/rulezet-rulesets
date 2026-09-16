rule TTP_XOR_QUAD_CurrentVersionRun_f83c {
  strings:
    $key_f83c = { ab 53 [2] 8f 5d [2] a4 71 [2] 8a 53 [2] 9e 48 [2] 91 52 [2] 8f 4f [2] 8d 4e [2] 96 48 [2] 8a 4f [2] 96 60 }

  condition:
    any of them
}