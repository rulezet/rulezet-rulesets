rule TTP_XOR_MULT_DOSStub_6daf {
  strings:
    $key_6daf = { 39 c7 [2] 4d df [2] 0a dd [2] 4d cc [2] 03 c0 [2] 0f ca [2] 18 c1 [2] 03 8f [2] 3e }

  condition:
    any of them
}