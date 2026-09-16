rule TTP_XOR_MULT_DOSStub_caed {
  strings:
    $key_caed = { 9e 85 [2] ea 9d [2] ad 9f [2] ea 8e [2] a4 82 [2] a8 88 [2] bf 83 [2] a4 cd [2] 99 }

  condition:
    any of them
}