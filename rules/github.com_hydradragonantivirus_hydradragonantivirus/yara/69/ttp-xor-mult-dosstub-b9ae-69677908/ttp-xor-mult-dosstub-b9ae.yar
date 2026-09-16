rule TTP_XOR_MULT_DOSStub_b9ae {
  strings:
    $key_b9ae = { ed c6 [2] 99 de [2] de dc [2] 99 cd [2] d7 c1 [2] db cb [2] cc c0 [2] d7 8e [2] ea }

  condition:
    any of them
}