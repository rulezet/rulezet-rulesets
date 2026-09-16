rule TTP_XOR_MULT_DOSStub_f56f {
  strings:
    $key_f56f = { a1 07 [2] d5 1f [2] 92 1d [2] d5 0c [2] 9b 00 [2] 97 0a [2] 80 01 [2] 9b 4f [2] a6 }

  condition:
    any of them
}