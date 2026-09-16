rule TTP_XOR_MULT_DOSStub_61af {
  strings:
    $key_61af = { 35 c7 [2] 41 df [2] 06 dd [2] 41 cc [2] 0f c0 [2] 03 ca [2] 14 c1 [2] 0f 8f [2] 32 }

  condition:
    any of them
}