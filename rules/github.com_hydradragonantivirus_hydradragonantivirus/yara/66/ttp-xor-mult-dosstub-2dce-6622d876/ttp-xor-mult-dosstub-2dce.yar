rule TTP_XOR_MULT_DOSStub_2dce {
  strings:
    $key_2dce = { 79 a6 [2] 0d be [2] 4a bc [2] 0d ad [2] 43 a1 [2] 4f ab [2] 58 a0 [2] 43 ee [2] 7e }

  condition:
    any of them
}