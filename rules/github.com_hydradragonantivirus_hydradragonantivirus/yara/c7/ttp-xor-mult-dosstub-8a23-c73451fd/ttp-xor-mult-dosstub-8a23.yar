rule TTP_XOR_MULT_DOSStub_8a23 {
  strings:
    $key_8a23 = { de 4b [2] aa 53 [2] ed 51 [2] aa 40 [2] e4 4c [2] e8 46 [2] ff 4d [2] e4 03 [2] d9 }

  condition:
    any of them
}