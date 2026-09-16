rule TTP_XOR_MULT_DOSStub_dc99 {
  strings:
    $key_dc99 = { 88 f1 [2] fc e9 [2] bb eb [2] fc fa [2] b2 f6 [2] be fc [2] a9 f7 [2] b2 b9 [2] 8f }

  condition:
    any of them
}