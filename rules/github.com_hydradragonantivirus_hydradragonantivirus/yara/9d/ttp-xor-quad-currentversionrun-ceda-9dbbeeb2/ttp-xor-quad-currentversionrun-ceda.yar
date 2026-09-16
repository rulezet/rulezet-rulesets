rule TTP_XOR_QUAD_CurrentVersionRun_ceda {
  strings:
    $key_ceda = { 9d b5 [2] b9 bb [2] 92 97 [2] bc b5 [2] a8 ae [2] a7 b4 [2] b9 a9 [2] bb a8 [2] a0 ae [2] bc a9 [2] a0 86 }

  condition:
    any of them
}