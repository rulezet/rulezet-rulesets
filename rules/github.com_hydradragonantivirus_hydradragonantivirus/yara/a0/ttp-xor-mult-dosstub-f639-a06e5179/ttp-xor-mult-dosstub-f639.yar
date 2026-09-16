rule TTP_XOR_MULT_DOSStub_f639 {
  strings:
    $key_f639 = { a2 51 [2] d6 49 [2] 91 4b [2] d6 5a [2] 98 56 [2] 94 5c [2] 83 57 [2] 98 19 [2] a5 }

  condition:
    any of them
}