rule TTP_XOR_MULT_DOSStub_a8db {
  strings:
    $key_a8db = { fc b3 [2] 88 ab [2] cf a9 [2] 88 b8 [2] c6 b4 [2] ca be [2] dd b5 [2] c6 fb [2] fb }

  condition:
    any of them
}