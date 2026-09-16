rule TTP_XOR_MULT_DOSStub_53af {
  strings:
    $key_53af = { 07 c7 [2] 73 df [2] 34 dd [2] 73 cc [2] 3d c0 [2] 31 ca [2] 26 c1 [2] 3d 8f [2] 00 }

  condition:
    any of them
}