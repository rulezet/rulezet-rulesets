rule TTP_XOR_MULT_DOSStub_b96c {
  strings:
    $key_b96c = { ed 04 [2] 99 1c [2] de 1e [2] 99 0f [2] d7 03 [2] db 09 [2] cc 02 [2] d7 4c [2] ea }

  condition:
    any of them
}