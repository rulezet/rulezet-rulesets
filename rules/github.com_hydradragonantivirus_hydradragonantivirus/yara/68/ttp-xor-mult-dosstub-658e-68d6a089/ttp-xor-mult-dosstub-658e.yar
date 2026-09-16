rule TTP_XOR_MULT_DOSStub_658e {
  strings:
    $key_658e = { 31 e6 [2] 45 fe [2] 02 fc [2] 45 ed [2] 0b e1 [2] 07 eb [2] 10 e0 [2] 0b ae [2] 36 }

  condition:
    any of them
}