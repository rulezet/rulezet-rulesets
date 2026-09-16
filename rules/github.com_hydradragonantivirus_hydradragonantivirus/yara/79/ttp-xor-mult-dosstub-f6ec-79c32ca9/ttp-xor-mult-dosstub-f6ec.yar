rule TTP_XOR_MULT_DOSStub_f6ec {
  strings:
    $key_f6ec = { a2 84 [2] d6 9c [2] 91 9e [2] d6 8f [2] 98 83 [2] 94 89 [2] 83 82 [2] 98 cc [2] a5 }

  condition:
    any of them
}