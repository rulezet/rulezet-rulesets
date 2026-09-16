rule TTP_XOR_MULT_DOSStub_c32f {
  strings:
    $key_c32f = { 97 47 [2] e3 5f [2] a4 5d [2] e3 4c [2] ad 40 [2] a1 4a [2] b6 41 [2] ad 0f [2] 90 }

  condition:
    any of them
}