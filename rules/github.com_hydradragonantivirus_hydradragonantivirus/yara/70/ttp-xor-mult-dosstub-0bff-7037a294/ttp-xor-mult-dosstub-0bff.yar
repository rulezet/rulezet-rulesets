rule TTP_XOR_MULT_DOSStub_0bff {
  strings:
    $key_0bff = { 5f 97 [2] 2b 8f [2] 6c 8d [2] 2b 9c [2] 65 90 [2] 69 9a [2] 7e 91 [2] 65 df [2] 58 }

  condition:
    any of them
}