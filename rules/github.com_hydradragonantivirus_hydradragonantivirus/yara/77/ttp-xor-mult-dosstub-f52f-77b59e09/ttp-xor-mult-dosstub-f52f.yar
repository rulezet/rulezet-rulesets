rule TTP_XOR_MULT_DOSStub_f52f {
  strings:
    $key_f52f = { a1 47 [2] d5 5f [2] 92 5d [2] d5 4c [2] 9b 40 [2] 97 4a [2] 80 41 [2] 9b 0f [2] a6 }

  condition:
    any of them
}