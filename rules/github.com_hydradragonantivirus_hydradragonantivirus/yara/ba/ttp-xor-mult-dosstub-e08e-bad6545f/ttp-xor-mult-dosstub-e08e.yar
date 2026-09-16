rule TTP_XOR_MULT_DOSStub_e08e {
  strings:
    $key_e08e = { b4 e6 [2] c0 fe [2] 87 fc [2] c0 ed [2] 8e e1 [2] 82 eb [2] 95 e0 [2] 8e ae [2] b3 }

  condition:
    any of them
}