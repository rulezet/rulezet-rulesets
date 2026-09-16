rule TTP_XOR_MULT_DOSStub_e9de {
  strings:
    $key_e9de = { bd b6 [2] c9 ae [2] 8e ac [2] c9 bd [2] 87 b1 [2] 8b bb [2] 9c b0 [2] 87 fe [2] ba }

  condition:
    any of them
}