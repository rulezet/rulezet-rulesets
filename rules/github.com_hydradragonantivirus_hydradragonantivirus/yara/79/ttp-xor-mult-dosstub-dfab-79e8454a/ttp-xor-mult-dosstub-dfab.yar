rule TTP_XOR_MULT_DOSStub_dfab {
  strings:
    $key_dfab = { 8b c3 [2] ff db [2] b8 d9 [2] ff c8 [2] b1 c4 [2] bd ce [2] aa c5 [2] b1 8b [2] 8c }

  condition:
    any of them
}