rule TTP_XOR_QUAD_CurrentVersionRun_c9c1 {
  strings:
    $key_c9c1 = { 9a ae [2] be a0 [2] 95 8c [2] bb ae [2] af b5 [2] a0 af [2] be b2 [2] bc b3 [2] a7 b5 [2] bb b2 [2] a7 9d }

  condition:
    any of them
}