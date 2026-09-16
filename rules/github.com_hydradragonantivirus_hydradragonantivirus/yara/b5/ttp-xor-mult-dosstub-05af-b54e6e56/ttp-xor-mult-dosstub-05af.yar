rule TTP_XOR_MULT_DOSStub_05af {
  strings:
    $key_05af = { 51 c7 [2] 25 df [2] 62 dd [2] 25 cc [2] 6b c0 [2] 67 ca [2] 70 c1 [2] 6b 8f [2] 56 }

  condition:
    any of them
}