rule TTP_XOR_MULT_DOSStub_6acb {
  strings:
    $key_6acb = { 3e a3 [2] 4a bb [2] 0d b9 [2] 4a a8 [2] 04 a4 [2] 08 ae [2] 1f a5 [2] 04 eb [2] 39 }

  condition:
    any of them
}