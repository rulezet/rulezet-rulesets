rule TTP_XOR_MULT_DOSStub_b12f {
  strings:
    $key_b12f = { e5 47 [2] 91 5f [2] d6 5d [2] 91 4c [2] df 40 [2] d3 4a [2] c4 41 [2] df 0f [2] e2 }

  condition:
    any of them
}