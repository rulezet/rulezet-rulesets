rule TTP_XOR_MULT_DOSStub_0f99 {
  strings:
    $key_0f99 = { 5b f1 [2] 2f e9 [2] 68 eb [2] 2f fa [2] 61 f6 [2] 6d fc [2] 7a f7 [2] 61 b9 [2] 5c }

  condition:
    any of them
}