rule TTP_XOR_MULT_DOSStub_7fff {
  strings:
    $key_7fff = { 2b 97 [2] 5f 8f [2] 18 8d [2] 5f 9c [2] 11 90 [2] 1d 9a [2] 0a 91 [2] 11 df [2] 2c }

  condition:
    any of them
}