rule TTP_XOR_QUAD_CurrentVersionRun_dcb0 {
  strings:
    $key_dcb0 = { 8f df [2] ab d1 [2] 80 fd [2] ae df [2] ba c4 [2] b5 de [2] ab c3 [2] a9 c2 [2] b2 c4 [2] ae c3 [2] b2 ec }

  condition:
    any of them
}