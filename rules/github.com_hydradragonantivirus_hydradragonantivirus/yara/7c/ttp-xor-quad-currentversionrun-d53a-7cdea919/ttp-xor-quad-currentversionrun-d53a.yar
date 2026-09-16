rule TTP_XOR_QUAD_CurrentVersionRun_d53a {
  strings:
    $key_d53a = { 86 55 [2] a2 5b [2] 89 77 [2] a7 55 [2] b3 4e [2] bc 54 [2] a2 49 [2] a0 48 [2] bb 4e [2] a7 49 [2] bb 66 }

  condition:
    any of them
}