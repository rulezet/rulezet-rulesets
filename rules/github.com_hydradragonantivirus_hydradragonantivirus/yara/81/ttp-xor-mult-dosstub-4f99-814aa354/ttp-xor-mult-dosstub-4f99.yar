rule TTP_XOR_MULT_DOSStub_4f99 {
  strings:
    $key_4f99 = { 1b f1 [2] 6f e9 [2] 28 eb [2] 6f fa [2] 21 f6 [2] 2d fc [2] 3a f7 [2] 21 b9 [2] 1c }

  condition:
    any of them
}