rule TTP_XOR_MULT_DOSStub_dddb {
  strings:
    $key_dddb = { 89 b3 [2] fd ab [2] ba a9 [2] fd b8 [2] b3 b4 [2] bf be [2] a8 b5 [2] b3 fb [2] 8e }

  condition:
    any of them
}