rule TTP_XOR_MULT_DOSStub_6f99 {
  strings:
    $key_6f99 = { 3b f1 [2] 4f e9 [2] 08 eb [2] 4f fa [2] 01 f6 [2] 0d fc [2] 1a f7 [2] 01 b9 [2] 3c }

  condition:
    any of them
}