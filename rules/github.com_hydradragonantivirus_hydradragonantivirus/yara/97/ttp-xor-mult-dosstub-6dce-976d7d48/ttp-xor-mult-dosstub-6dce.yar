rule TTP_XOR_MULT_DOSStub_6dce {
  strings:
    $key_6dce = { 39 a6 [2] 4d be [2] 0a bc [2] 4d ad [2] 03 a1 [2] 0f ab [2] 18 a0 [2] 03 ee [2] 3e }

  condition:
    any of them
}