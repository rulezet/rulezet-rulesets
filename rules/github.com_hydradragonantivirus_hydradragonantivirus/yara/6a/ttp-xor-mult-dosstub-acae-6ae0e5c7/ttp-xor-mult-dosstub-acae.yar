rule TTP_XOR_MULT_DOSStub_acae {
  strings:
    $key_acae = { f8 c6 [2] 8c de [2] cb dc [2] 8c cd [2] c2 c1 [2] ce cb [2] d9 c0 [2] c2 8e [2] ff }

  condition:
    any of them
}