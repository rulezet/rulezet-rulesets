rule TTP_XOR_MULT_DOSStub_72af {
  strings:
    $key_72af = { 26 c7 [2] 52 df [2] 15 dd [2] 52 cc [2] 1c c0 [2] 10 ca [2] 07 c1 [2] 1c 8f [2] 21 }

  condition:
    any of them
}