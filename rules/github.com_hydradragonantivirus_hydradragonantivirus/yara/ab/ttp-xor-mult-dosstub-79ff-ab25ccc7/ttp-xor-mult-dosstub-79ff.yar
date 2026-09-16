rule TTP_XOR_MULT_DOSStub_79ff {
  strings:
    $key_79ff = { 2d 97 [2] 59 8f [2] 1e 8d [2] 59 9c [2] 17 90 [2] 1b 9a [2] 0c 91 [2] 17 df [2] 2a }

  condition:
    any of them
}