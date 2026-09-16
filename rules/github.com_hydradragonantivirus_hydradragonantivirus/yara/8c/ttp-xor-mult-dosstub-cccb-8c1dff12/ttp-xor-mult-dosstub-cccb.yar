rule TTP_XOR_MULT_DOSStub_cccb {
  strings:
    $key_cccb = { 98 a3 [2] ec bb [2] ab b9 [2] ec a8 [2] a2 a4 [2] ae ae [2] b9 a5 [2] a2 eb [2] 9f }

  condition:
    any of them
}