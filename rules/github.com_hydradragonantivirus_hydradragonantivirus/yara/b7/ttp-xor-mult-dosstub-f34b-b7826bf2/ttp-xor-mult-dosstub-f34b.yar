rule TTP_XOR_MULT_DOSStub_f34b {
  strings:
    $key_f34b = { a7 23 [2] d3 3b [2] 94 39 [2] d3 28 [2] 9d 24 [2] 91 2e [2] 86 25 [2] 9d 6b [2] a0 }

  condition:
    any of them
}