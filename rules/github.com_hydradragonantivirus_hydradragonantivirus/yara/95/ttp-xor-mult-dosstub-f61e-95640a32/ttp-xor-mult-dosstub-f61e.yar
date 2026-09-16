rule TTP_XOR_MULT_DOSStub_f61e {
  strings:
    $key_f61e = { a2 76 [2] d6 6e [2] 91 6c [2] d6 7d [2] 98 71 [2] 94 7b [2] 83 70 [2] 98 3e [2] a5 }

  condition:
    any of them
}