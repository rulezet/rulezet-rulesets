rule TTP_XOR_MULT_DOSStub_27af {
  strings:
    $key_27af = { 73 c7 [2] 07 df [2] 40 dd [2] 07 cc [2] 49 c0 [2] 45 ca [2] 52 c1 [2] 49 8f [2] 74 }

  condition:
    any of them
}