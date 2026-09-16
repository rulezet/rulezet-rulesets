rule TTP_XOR_MULT_DOSStub_35af {
  strings:
    $key_35af = { 61 c7 [2] 15 df [2] 52 dd [2] 15 cc [2] 5b c0 [2] 57 ca [2] 40 c1 [2] 5b 8f [2] 66 }

  condition:
    any of them
}