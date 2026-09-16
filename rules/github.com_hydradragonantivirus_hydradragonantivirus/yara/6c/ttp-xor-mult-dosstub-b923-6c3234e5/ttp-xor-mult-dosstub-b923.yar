rule TTP_XOR_MULT_DOSStub_b923 {
  strings:
    $key_b923 = { ed 4b [2] 99 53 [2] de 51 [2] 99 40 [2] d7 4c [2] db 46 [2] cc 4d [2] d7 03 [2] ea }

  condition:
    any of them
}