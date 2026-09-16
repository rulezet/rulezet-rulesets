rule TTP_XOR_MULT_DOSStub_fdb8 {
  strings:
    $key_fdb8 = { a9 d0 [2] dd c8 [2] 9a ca [2] dd db [2] 93 d7 [2] 9f dd [2] 88 d6 [2] 93 98 [2] ae }

  condition:
    any of them
}