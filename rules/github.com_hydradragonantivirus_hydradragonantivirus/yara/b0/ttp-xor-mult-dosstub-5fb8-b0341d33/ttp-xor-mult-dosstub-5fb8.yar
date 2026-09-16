rule TTP_XOR_MULT_DOSStub_5fb8 {
  strings:
    $key_5fb8 = { 0b d0 [2] 7f c8 [2] 38 ca [2] 7f db [2] 31 d7 [2] 3d dd [2] 2a d6 [2] 31 98 [2] 0c }

  condition:
    any of them
}