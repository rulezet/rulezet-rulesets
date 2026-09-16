rule TTP_XOR_MULT_DOSStub_6383 {
  strings:
    $key_6383 = { 37 eb [2] 43 f3 [2] 04 f1 [2] 43 e0 [2] 0d ec [2] 01 e6 [2] 16 ed [2] 0d a3 [2] 30 }

  condition:
    any of them
}