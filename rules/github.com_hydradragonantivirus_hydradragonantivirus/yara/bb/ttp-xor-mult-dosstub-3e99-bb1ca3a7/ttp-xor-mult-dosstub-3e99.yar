rule TTP_XOR_MULT_DOSStub_3e99 {
  strings:
    $key_3e99 = { 6a f1 [2] 1e e9 [2] 59 eb [2] 1e fa [2] 50 f6 [2] 5c fc [2] 4b f7 [2] 50 b9 [2] 6d }

  condition:
    any of them
}