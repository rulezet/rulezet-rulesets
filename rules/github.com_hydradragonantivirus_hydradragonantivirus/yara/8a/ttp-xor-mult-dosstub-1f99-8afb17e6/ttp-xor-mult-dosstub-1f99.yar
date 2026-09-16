rule TTP_XOR_MULT_DOSStub_1f99 {
  strings:
    $key_1f99 = { 4b f1 [2] 3f e9 [2] 78 eb [2] 3f fa [2] 71 f6 [2] 7d fc [2] 6a f7 [2] 71 b9 [2] 4c }

  condition:
    any of them
}