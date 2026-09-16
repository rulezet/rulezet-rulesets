rule TTP_XOR_MULT_DOSStub_f01e {
  strings:
    $key_f01e = { a4 76 [2] d0 6e [2] 97 6c [2] d0 7d [2] 9e 71 [2] 92 7b [2] 85 70 [2] 9e 3e [2] a3 }

  condition:
    any of them
}