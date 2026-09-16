rule TTP_XOR_MULT_DOSStub_b5ff {
  strings:
    $key_b5ff = { e1 97 [2] 95 8f [2] d2 8d [2] 95 9c [2] db 90 [2] d7 9a [2] c0 91 [2] db df [2] e6 }

  condition:
    any of them
}