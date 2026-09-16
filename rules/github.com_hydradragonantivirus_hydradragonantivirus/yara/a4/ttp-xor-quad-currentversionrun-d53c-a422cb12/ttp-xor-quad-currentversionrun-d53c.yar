rule TTP_XOR_QUAD_CurrentVersionRun_d53c {
  strings:
    $key_d53c = { 86 53 [2] a2 5d [2] 89 71 [2] a7 53 [2] b3 48 [2] bc 52 [2] a2 4f [2] a0 4e [2] bb 48 [2] a7 4f [2] bb 60 }

  condition:
    any of them
}