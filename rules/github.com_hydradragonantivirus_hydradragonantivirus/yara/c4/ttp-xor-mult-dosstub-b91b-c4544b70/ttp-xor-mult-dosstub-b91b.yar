rule TTP_XOR_MULT_DOSStub_b91b {
  strings:
    $key_b91b = { ed 73 [2] 99 6b [2] de 69 [2] 99 78 [2] d7 74 [2] db 7e [2] cc 75 [2] d7 3b [2] ea }

  condition:
    any of them
}