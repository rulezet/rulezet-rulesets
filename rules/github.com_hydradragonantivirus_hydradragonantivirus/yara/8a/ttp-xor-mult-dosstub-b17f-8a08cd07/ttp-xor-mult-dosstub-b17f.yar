rule TTP_XOR_MULT_DOSStub_b17f {
  strings:
    $key_b17f = { e5 17 [2] 91 0f [2] d6 0d [2] 91 1c [2] df 10 [2] d3 1a [2] c4 11 [2] df 5f [2] e2 }

  condition:
    any of them
}