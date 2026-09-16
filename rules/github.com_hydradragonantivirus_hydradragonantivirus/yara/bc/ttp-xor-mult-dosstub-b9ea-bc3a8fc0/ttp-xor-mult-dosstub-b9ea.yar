rule TTP_XOR_MULT_DOSStub_b9ea {
  strings:
    $key_b9ea = { ed 82 [2] 99 9a [2] de 98 [2] 99 89 [2] d7 85 [2] db 8f [2] cc 84 [2] d7 ca [2] ea }

  condition:
    any of them
}