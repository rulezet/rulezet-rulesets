rule TTP_XOR_MULT_DOSStub_1bff {
  strings:
    $key_1bff = { 4f 97 [2] 3b 8f [2] 7c 8d [2] 3b 9c [2] 75 90 [2] 79 9a [2] 6e 91 [2] 75 df [2] 48 }

  condition:
    any of them
}