rule TTP_XOR_MULT_DOSStub_eacc {
  strings:
    $key_eacc = { be a4 [2] ca bc [2] 8d be [2] ca af [2] 84 a3 [2] 88 a9 [2] 9f a2 [2] 84 ec [2] b9 }

  condition:
    any of them
}