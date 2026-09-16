rule TTP_XOR_MULT_DOSStub_7dce {
  strings:
    $key_7dce = { 29 a6 [2] 5d be [2] 1a bc [2] 5d ad [2] 13 a1 [2] 1f ab [2] 08 a0 [2] 13 ee [2] 2e }

  condition:
    any of them
}