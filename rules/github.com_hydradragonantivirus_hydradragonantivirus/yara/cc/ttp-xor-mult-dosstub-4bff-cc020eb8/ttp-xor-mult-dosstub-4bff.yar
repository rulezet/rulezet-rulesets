rule TTP_XOR_MULT_DOSStub_4bff {
  strings:
    $key_4bff = { 1f 97 [2] 6b 8f [2] 2c 8d [2] 6b 9c [2] 25 90 [2] 29 9a [2] 3e 91 [2] 25 df [2] 18 }

  condition:
    any of them
}