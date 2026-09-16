rule TTP_XOR_MULT_DOSStub_4dce {
  strings:
    $key_4dce = { 19 a6 [2] 6d be [2] 2a bc [2] 6d ad [2] 23 a1 [2] 2f ab [2] 38 a0 [2] 23 ee [2] 1e }

  condition:
    any of them
}