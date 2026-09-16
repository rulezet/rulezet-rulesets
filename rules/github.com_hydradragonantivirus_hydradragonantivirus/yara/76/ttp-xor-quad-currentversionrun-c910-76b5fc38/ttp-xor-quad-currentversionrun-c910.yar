rule TTP_XOR_QUAD_CurrentVersionRun_c910 {
  strings:
    $key_c910 = { 9a 7f [2] be 71 [2] 95 5d [2] bb 7f [2] af 64 [2] a0 7e [2] be 63 [2] bc 62 [2] a7 64 [2] bb 63 [2] a7 4c }

  condition:
    any of them
}