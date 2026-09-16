rule TTP_XOR_MULT_DOSStub_f6ae {
  strings:
    $key_f6ae = { a2 c6 [2] d6 de [2] 91 dc [2] d6 cd [2] 98 c1 [2] 94 cb [2] 83 c0 [2] 98 8e [2] a5 }

  condition:
    any of them
}