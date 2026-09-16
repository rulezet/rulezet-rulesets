rule TTP_XOR_QUAD_CurrentVersionRun_cbe2 {
  strings:
    $key_cbe2 = { 98 8d [2] bc 83 [2] 97 af [2] b9 8d [2] ad 96 [2] a2 8c [2] bc 91 [2] be 90 [2] a5 96 [2] b9 91 [2] a5 be }

  condition:
    any of them
}