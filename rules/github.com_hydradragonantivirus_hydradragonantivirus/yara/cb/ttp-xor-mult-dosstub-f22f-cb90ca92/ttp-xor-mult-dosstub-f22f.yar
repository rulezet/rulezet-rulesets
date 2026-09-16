rule TTP_XOR_MULT_DOSStub_f22f {
  strings:
    $key_f22f = { a6 47 [2] d2 5f [2] 95 5d [2] d2 4c [2] 9c 40 [2] 90 4a [2] 87 41 [2] 9c 0f [2] a1 }

  condition:
    any of them
}