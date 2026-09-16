rule TTP_XOR_MULT_DOSStub_d12c {
  strings:
    $key_d12c = { 85 44 [2] f1 5c [2] b6 5e [2] f1 4f [2] bf 43 [2] b3 49 [2] a4 42 [2] bf 0c [2] 82 }

  condition:
    any of them
}