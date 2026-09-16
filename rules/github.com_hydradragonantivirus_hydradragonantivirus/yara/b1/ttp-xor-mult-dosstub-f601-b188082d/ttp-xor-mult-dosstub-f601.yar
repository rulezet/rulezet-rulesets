rule TTP_XOR_MULT_DOSStub_f601 {
  strings:
    $key_f601 = { a2 69 [2] d6 71 [2] 91 73 [2] d6 62 [2] 98 6e [2] 94 64 [2] 83 6f [2] 98 21 [2] a5 }

  condition:
    any of them
}