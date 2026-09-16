rule TTP_XOR_QUAD_CurrentVersionRun_cbe3 {
  strings:
    $key_cbe3 = { 98 8c [2] bc 82 [2] 97 ae [2] b9 8c [2] ad 97 [2] a2 8d [2] bc 90 [2] be 91 [2] a5 97 [2] b9 90 [2] a5 bf }

  condition:
    any of them
}