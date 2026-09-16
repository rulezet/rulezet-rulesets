rule TTP_XOR_MULT_DOSStub_f60f {
  strings:
    $key_f60f = { a2 67 [2] d6 7f [2] 91 7d [2] d6 6c [2] 98 60 [2] 94 6a [2] 83 61 [2] 98 2f [2] a5 }

  condition:
    any of them
}