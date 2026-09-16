rule TTP_XOR_MULT_DOSStub_203c {
  strings:
    $key_203c = { 74 54 [2] 00 4c [2] 47 4e [2] 00 5f [2] 4e 53 [2] 42 59 [2] 55 52 [2] 4e 1c [2] 73 }

  condition:
    any of them
}