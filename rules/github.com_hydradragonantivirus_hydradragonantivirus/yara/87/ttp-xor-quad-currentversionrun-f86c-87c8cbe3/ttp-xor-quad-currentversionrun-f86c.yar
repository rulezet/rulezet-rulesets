rule TTP_XOR_QUAD_CurrentVersionRun_f86c {
  strings:
    $key_f86c = { ab 03 [2] 8f 0d [2] a4 21 [2] 8a 03 [2] 9e 18 [2] 91 02 [2] 8f 1f [2] 8d 1e [2] 96 18 [2] 8a 1f [2] 96 30 }

  condition:
    any of them
}