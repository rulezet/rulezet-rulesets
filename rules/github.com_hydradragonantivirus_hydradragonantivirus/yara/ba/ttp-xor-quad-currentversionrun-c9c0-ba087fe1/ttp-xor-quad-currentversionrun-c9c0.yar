rule TTP_XOR_QUAD_CurrentVersionRun_c9c0 {
  strings:
    $key_c9c0 = { 9a af [2] be a1 [2] 95 8d [2] bb af [2] af b4 [2] a0 ae [2] be b3 [2] bc b2 [2] a7 b4 [2] bb b3 [2] a7 9c }

  condition:
    any of them
}