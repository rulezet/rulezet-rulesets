rule TTP_XOR_MULT_DOSStub_b7ff {
  strings:
    $key_b7ff = { e3 97 [2] 97 8f [2] d0 8d [2] 97 9c [2] d9 90 [2] d5 9a [2] c2 91 [2] d9 df [2] e4 }

  condition:
    any of them
}