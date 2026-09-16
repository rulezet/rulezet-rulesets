rule TTP_XOR_QUAD_CurrentVersionRun_f82e {
  strings:
    $key_f82e = { ab 41 [2] 8f 4f [2] a4 63 [2] 8a 41 [2] 9e 5a [2] 91 40 [2] 8f 5d [2] 8d 5c [2] 96 5a [2] 8a 5d [2] 96 72 }

  condition:
    any of them
}