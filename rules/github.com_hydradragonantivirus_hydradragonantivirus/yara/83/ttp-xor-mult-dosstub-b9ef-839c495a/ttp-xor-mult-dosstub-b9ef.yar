rule TTP_XOR_MULT_DOSStub_b9ef {
  strings:
    $key_b9ef = { ed 87 [2] 99 9f [2] de 9d [2] 99 8c [2] d7 80 [2] db 8a [2] cc 81 [2] d7 cf [2] ea }

  condition:
    any of them
}