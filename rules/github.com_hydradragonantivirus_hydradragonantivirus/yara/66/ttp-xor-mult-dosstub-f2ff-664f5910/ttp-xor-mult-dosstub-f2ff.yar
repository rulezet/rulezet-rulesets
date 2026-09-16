rule TTP_XOR_MULT_DOSStub_f2ff {
  strings:
    $key_f2ff = { a6 97 [2] d2 8f [2] 95 8d [2] d2 9c [2] 9c 90 [2] 90 9a [2] 87 91 [2] 9c df [2] a1 }

  condition:
    any of them
}