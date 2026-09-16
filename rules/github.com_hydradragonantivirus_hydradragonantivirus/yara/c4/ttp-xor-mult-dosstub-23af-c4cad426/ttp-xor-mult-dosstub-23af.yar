rule TTP_XOR_MULT_DOSStub_23af {
  strings:
    $key_23af = { 77 c7 [2] 03 df [2] 44 dd [2] 03 cc [2] 4d c0 [2] 41 ca [2] 56 c1 [2] 4d 8f [2] 70 }

  condition:
    any of them
}