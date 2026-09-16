rule TTP_XOR_MULT_DOSStub_59ff {
  strings:
    $key_59ff = { 0d 97 [2] 79 8f [2] 3e 8d [2] 79 9c [2] 37 90 [2] 3b 9a [2] 2c 91 [2] 37 df [2] 0a }

  condition:
    any of them
}