rule TTP_XOR_MULT_DOSStub_e01c {
  strings:
    $key_e01c = { b4 74 [2] c0 6c [2] 87 6e [2] c0 7f [2] 8e 73 [2] 82 79 [2] 95 72 [2] 8e 3c [2] b3 }

  condition:
    any of them
}