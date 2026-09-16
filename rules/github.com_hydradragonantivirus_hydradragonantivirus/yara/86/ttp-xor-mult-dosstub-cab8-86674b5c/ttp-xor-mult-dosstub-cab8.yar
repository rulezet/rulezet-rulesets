rule TTP_XOR_MULT_DOSStub_cab8 {
  strings:
    $key_cab8 = { 9e d0 [2] ea c8 [2] ad ca [2] ea db [2] a4 d7 [2] a8 dd [2] bf d6 [2] a4 98 [2] 99 }

  condition:
    any of them
}