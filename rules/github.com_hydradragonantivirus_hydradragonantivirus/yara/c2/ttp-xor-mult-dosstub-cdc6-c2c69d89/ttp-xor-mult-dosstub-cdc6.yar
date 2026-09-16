rule TTP_XOR_MULT_DOSStub_cdc6 {
  strings:
    $key_cdc6 = { 99 ae [2] ed b6 [2] aa b4 [2] ed a5 [2] a3 a9 [2] af a3 [2] b8 a8 [2] a3 e6 [2] 9e }

  condition:
    any of them
}