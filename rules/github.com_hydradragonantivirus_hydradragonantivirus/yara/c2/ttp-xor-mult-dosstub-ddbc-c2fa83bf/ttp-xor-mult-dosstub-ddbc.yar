rule TTP_XOR_MULT_DOSStub_ddbc {
  strings:
    $key_ddbc = { 89 d4 [2] fd cc [2] ba ce [2] fd df [2] b3 d3 [2] bf d9 [2] a8 d2 [2] b3 9c [2] 8e }

  condition:
    any of them
}