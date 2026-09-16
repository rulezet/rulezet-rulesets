rule TTP_XOR_MULT_DOSStub_12af {
  strings:
    $key_12af = { 46 c7 [2] 32 df [2] 75 dd [2] 32 cc [2] 7c c0 [2] 70 ca [2] 67 c1 [2] 7c 8f [2] 41 }

  condition:
    any of them
}