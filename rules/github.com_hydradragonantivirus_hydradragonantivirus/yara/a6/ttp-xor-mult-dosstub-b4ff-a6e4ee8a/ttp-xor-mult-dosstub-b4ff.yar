rule TTP_XOR_MULT_DOSStub_b4ff {
  strings:
    $key_b4ff = { e0 97 [2] 94 8f [2] d3 8d [2] 94 9c [2] da 90 [2] d6 9a [2] c1 91 [2] da df [2] e7 }

  condition:
    any of them
}