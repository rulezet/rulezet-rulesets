rule TTP_XOR_MULT_DOSStub_0e99 {
  strings:
    $key_0e99 = { 5a f1 [2] 2e e9 [2] 69 eb [2] 2e fa [2] 60 f6 [2] 6c fc [2] 7b f7 [2] 60 b9 [2] 5d }

  condition:
    any of them
}