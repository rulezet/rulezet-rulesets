rule TTP_XOR_QUAD_CurrentVersionRun_dcb6 {
  strings:
    $key_dcb6 = { 8f d9 [2] ab d7 [2] 80 fb [2] ae d9 [2] ba c2 [2] b5 d8 [2] ab c5 [2] a9 c4 [2] b2 c2 [2] ae c5 [2] b2 ea }

  condition:
    any of them
}