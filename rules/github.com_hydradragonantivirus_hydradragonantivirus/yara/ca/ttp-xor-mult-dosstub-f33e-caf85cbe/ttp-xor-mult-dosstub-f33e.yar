rule TTP_XOR_MULT_DOSStub_f33e {
  strings:
    $key_f33e = { a7 56 [2] d3 4e [2] 94 4c [2] d3 5d [2] 9d 51 [2] 91 5b [2] 86 50 [2] 9d 1e [2] a0 }

  condition:
    any of them
}