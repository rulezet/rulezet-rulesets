rule TTP_XOR_MULT_DOSStub_7f99 {
  strings:
    $key_7f99 = { 2b f1 [2] 5f e9 [2] 18 eb [2] 5f fa [2] 11 f6 [2] 1d fc [2] 0a f7 [2] 11 b9 [2] 2c }

  condition:
    any of them
}