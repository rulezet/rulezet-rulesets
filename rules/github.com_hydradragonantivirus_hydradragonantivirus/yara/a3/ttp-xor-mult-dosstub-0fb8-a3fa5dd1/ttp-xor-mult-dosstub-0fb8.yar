rule TTP_XOR_MULT_DOSStub_0fb8 {
  strings:
    $key_0fb8 = { 5b d0 [2] 2f c8 [2] 68 ca [2] 2f db [2] 61 d7 [2] 6d dd [2] 7a d6 [2] 61 98 [2] 5c }

  condition:
    any of them
}