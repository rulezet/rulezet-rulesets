rule TTP_XOR_MULT_DOSStub_b3ff {
  strings:
    $key_b3ff = { e7 97 [2] 93 8f [2] d4 8d [2] 93 9c [2] dd 90 [2] d1 9a [2] c6 91 [2] dd df [2] e0 }

  condition:
    any of them
}