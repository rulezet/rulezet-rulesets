rule TTP_XOR_QUAD_CurrentVersionRun_dcb3 {
  strings:
    $key_dcb3 = { 8f dc [2] ab d2 [2] 80 fe [2] ae dc [2] ba c7 [2] b5 dd [2] ab c0 [2] a9 c1 [2] b2 c7 [2] ae c0 [2] b2 ef }

  condition:
    any of them
}