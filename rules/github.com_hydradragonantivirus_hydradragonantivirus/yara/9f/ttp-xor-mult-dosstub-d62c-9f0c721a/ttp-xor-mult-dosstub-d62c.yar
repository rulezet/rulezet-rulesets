rule TTP_XOR_MULT_DOSStub_d62c {
  strings:
    $key_d62c = { 82 44 [2] f6 5c [2] b1 5e [2] f6 4f [2] b8 43 [2] b4 49 [2] a3 42 [2] b8 0c [2] 85 }

  condition:
    any of them
}