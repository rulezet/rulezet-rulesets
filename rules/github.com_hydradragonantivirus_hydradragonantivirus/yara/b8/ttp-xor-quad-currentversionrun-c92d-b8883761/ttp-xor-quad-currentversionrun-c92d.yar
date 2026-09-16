rule TTP_XOR_QUAD_CurrentVersionRun_c92d {
  strings:
    $key_c92d = { 9a 42 [2] be 4c [2] 95 60 [2] bb 42 [2] af 59 [2] a0 43 [2] be 5e [2] bc 5f [2] a7 59 [2] bb 5e [2] a7 71 }

  condition:
    any of them
}