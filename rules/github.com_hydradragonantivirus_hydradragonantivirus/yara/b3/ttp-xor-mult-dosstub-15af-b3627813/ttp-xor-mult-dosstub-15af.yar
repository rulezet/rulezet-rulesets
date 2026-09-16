rule TTP_XOR_MULT_DOSStub_15af {
  strings:
    $key_15af = { 41 c7 [2] 35 df [2] 72 dd [2] 35 cc [2] 7b c0 [2] 77 ca [2] 60 c1 [2] 7b 8f [2] 46 }

  condition:
    any of them
}