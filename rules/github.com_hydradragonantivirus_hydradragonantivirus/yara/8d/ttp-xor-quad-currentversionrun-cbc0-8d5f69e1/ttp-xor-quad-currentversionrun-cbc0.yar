rule TTP_XOR_QUAD_CurrentVersionRun_cbc0 {
  strings:
    $key_cbc0 = { 98 af [2] bc a1 [2] 97 8d [2] b9 af [2] ad b4 [2] a2 ae [2] bc b3 [2] be b2 [2] a5 b4 [2] b9 b3 [2] a5 9c }

  condition:
    any of them
}