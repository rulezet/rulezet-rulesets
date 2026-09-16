rule TTP_XOR_MULT_DOSStub_facc {
  strings:
    $key_facc = { ae a4 [2] da bc [2] 9d be [2] da af [2] 94 a3 [2] 98 a9 [2] 8f a2 [2] 94 ec [2] a9 }

  condition:
    any of them
}