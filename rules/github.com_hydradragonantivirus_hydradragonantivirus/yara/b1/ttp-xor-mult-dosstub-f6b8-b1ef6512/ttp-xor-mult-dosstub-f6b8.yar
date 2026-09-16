rule TTP_XOR_MULT_DOSStub_f6b8 {
  strings:
    $key_f6b8 = { a2 d0 [2] d6 c8 [2] 91 ca [2] d6 db [2] 98 d7 [2] 94 dd [2] 83 d6 [2] 98 98 [2] a5 }

  condition:
    any of them
}