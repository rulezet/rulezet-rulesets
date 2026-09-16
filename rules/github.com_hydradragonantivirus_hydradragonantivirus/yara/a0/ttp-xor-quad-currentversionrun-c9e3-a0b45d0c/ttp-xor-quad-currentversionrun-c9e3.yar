rule TTP_XOR_QUAD_CurrentVersionRun_c9e3 {
  strings:
    $key_c9e3 = { 9a 8c [2] be 82 [2] 95 ae [2] bb 8c [2] af 97 [2] a0 8d [2] be 90 [2] bc 91 [2] a7 97 [2] bb 90 [2] a7 bf }

  condition:
    any of them
}