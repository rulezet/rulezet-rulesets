rule TTP_XOR_MULT_DOSStub_efb8 {
  strings:
    $key_efb8 = { bb d0 [2] cf c8 [2] 88 ca [2] cf db [2] 81 d7 [2] 8d dd [2] 9a d6 [2] 81 98 [2] bc }

  condition:
    any of them
}