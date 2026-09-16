rule TTP_XOR_MULT_DOSStub_f6eb {
  strings:
    $key_f6eb = { a2 83 [2] d6 9b [2] 91 99 [2] d6 88 [2] 98 84 [2] 94 8e [2] 83 85 [2] 98 cb [2] a5 }

  condition:
    any of them
}