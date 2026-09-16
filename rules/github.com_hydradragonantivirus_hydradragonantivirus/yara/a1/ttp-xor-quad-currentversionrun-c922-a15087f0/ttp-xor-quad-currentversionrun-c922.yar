rule TTP_XOR_QUAD_CurrentVersionRun_c922 {
  strings:
    $key_c922 = { 9a 4d [2] be 43 [2] 95 6f [2] bb 4d [2] af 56 [2] a0 4c [2] be 51 [2] bc 50 [2] a7 56 [2] bb 51 [2] a7 7e }

  condition:
    any of them
}