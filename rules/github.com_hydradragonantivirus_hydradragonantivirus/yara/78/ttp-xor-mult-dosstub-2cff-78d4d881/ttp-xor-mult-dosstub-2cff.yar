rule TTP_XOR_MULT_DOSStub_2cff {
  strings:
    $key_2cff = { 78 97 [2] 0c 8f [2] 4b 8d [2] 0c 9c [2] 42 90 [2] 4e 9a [2] 59 91 [2] 42 df [2] 7f }

  condition:
    any of them
}