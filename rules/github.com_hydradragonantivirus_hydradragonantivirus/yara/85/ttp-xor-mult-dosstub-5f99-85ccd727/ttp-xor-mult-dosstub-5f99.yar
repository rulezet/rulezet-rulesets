rule TTP_XOR_MULT_DOSStub_5f99 {
  strings:
    $key_5f99 = { 0b f1 [2] 7f e9 [2] 38 eb [2] 7f fa [2] 31 f6 [2] 3d fc [2] 2a f7 [2] 31 b9 [2] 0c }

  condition:
    any of them
}