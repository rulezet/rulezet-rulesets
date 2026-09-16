rule TTP_XOR_MULT_DOSStub_1aff {
  strings:
    $key_1aff = { 4e 97 [2] 3a 8f [2] 7d 8d [2] 3a 9c [2] 74 90 [2] 78 9a [2] 6f 91 [2] 74 df [2] 49 }

  condition:
    any of them
}