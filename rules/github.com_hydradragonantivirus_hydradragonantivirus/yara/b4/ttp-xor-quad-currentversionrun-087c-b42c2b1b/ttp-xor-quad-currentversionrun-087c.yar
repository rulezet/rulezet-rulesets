rule TTP_XOR_QUAD_CurrentVersionRun_087c {
  strings:
    $key_087c = { 5b 13 [2] 7f 1d [2] 54 31 [2] 7a 13 [2] 6e 08 [2] 61 12 [2] 7f 0f [2] 7d 0e [2] 66 08 [2] 7a 0f [2] 66 20 }

  condition:
    any of them
}