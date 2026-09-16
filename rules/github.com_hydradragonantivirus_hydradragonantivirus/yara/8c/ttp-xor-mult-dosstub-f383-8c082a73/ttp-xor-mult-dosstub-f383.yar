rule TTP_XOR_MULT_DOSStub_f383 {
  strings:
    $key_f383 = { a7 eb [2] d3 f3 [2] 94 f1 [2] d3 e0 [2] 9d ec [2] 91 e6 [2] 86 ed [2] 9d a3 [2] a0 }

  condition:
    any of them
}