rule TTP_XOR_MULT_DOSStub_b9b5 {
  strings:
    $key_b9b5 = { ed dd [2] 99 c5 [2] de c7 [2] 99 d6 [2] d7 da [2] db d0 [2] cc db [2] d7 95 [2] ea }

  condition:
    any of them
}