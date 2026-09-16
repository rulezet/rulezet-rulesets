rule TTP_XOR_QUAD_CurrentVersionRun_f856 {
  strings:
    $key_f856 = { ab 39 [2] 8f 37 [2] a4 1b [2] 8a 39 [2] 9e 22 [2] 91 38 [2] 8f 25 [2] 8d 24 [2] 96 22 [2] 8a 25 [2] 96 0a }

  condition:
    any of them
}