rule TTP_XOR_MULT_DOSStub_8a03 {
  strings:
    $key_8a03 = { de 6b [2] aa 73 [2] ed 71 [2] aa 60 [2] e4 6c [2] e8 66 [2] ff 6d [2] e4 23 [2] d9 }

  condition:
    any of them
}