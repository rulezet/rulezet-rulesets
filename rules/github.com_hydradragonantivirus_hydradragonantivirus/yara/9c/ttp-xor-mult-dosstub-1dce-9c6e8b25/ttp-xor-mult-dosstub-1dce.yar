rule TTP_XOR_MULT_DOSStub_1dce {
  strings:
    $key_1dce = { 49 a6 [2] 3d be [2] 7a bc [2] 3d ad [2] 73 a1 [2] 7f ab [2] 68 a0 [2] 73 ee [2] 4e }

  condition:
    any of them
}