rule TTP_XOR_MULT_DOSStub_62af {
  strings:
    $key_62af = { 36 c7 [2] 42 df [2] 05 dd [2] 42 cc [2] 0c c0 [2] 00 ca [2] 17 c1 [2] 0c 8f [2] 31 }

  condition:
    any of them
}