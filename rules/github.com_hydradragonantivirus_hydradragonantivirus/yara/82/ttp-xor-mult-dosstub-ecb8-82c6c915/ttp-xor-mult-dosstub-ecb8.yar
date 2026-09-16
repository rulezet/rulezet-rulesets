rule TTP_XOR_MULT_DOSStub_ecb8 {
  strings:
    $key_ecb8 = { b8 d0 [2] cc c8 [2] 8b ca [2] cc db [2] 82 d7 [2] 8e dd [2] 99 d6 [2] 82 98 [2] bf }

  condition:
    any of them
}