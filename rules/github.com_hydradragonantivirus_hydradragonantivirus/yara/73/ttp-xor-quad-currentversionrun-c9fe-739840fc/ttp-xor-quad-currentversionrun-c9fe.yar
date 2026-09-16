rule TTP_XOR_QUAD_CurrentVersionRun_c9fe {
  strings:
    $key_c9fe = { 9a 91 [2] be 9f [2] 95 b3 [2] bb 91 [2] af 8a [2] a0 90 [2] be 8d [2] bc 8c [2] a7 8a [2] bb 8d [2] a7 a2 }

  condition:
    any of them
}