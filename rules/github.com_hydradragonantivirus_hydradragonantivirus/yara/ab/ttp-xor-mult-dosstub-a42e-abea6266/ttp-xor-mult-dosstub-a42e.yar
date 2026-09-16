rule TTP_XOR_MULT_DOSStub_a42e {
  strings:
    $key_a42e = { f0 46 [2] 84 5e [2] c3 5c [2] 84 4d [2] ca 41 [2] c6 4b [2] d1 40 [2] ca 0e [2] f7 }

  condition:
    any of them
}