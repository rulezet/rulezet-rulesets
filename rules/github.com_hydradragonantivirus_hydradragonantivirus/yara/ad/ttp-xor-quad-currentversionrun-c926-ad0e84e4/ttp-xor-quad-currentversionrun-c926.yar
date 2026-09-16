rule TTP_XOR_QUAD_CurrentVersionRun_c926 {
  strings:
    $key_c926 = { 9a 49 [2] be 47 [2] 95 6b [2] bb 49 [2] af 52 [2] a0 48 [2] be 55 [2] bc 54 [2] a7 52 [2] bb 55 [2] a7 7a }

  condition:
    any of them
}