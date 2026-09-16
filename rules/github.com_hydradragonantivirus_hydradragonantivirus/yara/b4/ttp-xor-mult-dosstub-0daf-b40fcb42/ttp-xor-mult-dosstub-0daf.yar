rule TTP_XOR_MULT_DOSStub_0daf {
  strings:
    $key_0daf = { 59 c7 [2] 2d df [2] 6a dd [2] 2d cc [2] 63 c0 [2] 6f ca [2] 78 c1 [2] 63 8f [2] 5e }

  condition:
    any of them
}