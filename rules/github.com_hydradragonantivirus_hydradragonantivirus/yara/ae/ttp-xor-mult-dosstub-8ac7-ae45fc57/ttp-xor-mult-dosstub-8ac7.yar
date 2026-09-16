rule TTP_XOR_MULT_DOSStub_8ac7 {
  strings:
    $key_8ac7 = { de af [2] aa b7 [2] ed b5 [2] aa a4 [2] e4 a8 [2] e8 a2 [2] ff a9 [2] e4 e7 [2] d9 }

  condition:
    any of them
}