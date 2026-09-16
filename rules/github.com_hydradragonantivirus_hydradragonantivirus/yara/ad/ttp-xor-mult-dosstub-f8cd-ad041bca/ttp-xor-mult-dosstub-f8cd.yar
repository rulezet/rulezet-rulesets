rule TTP_XOR_MULT_DOSStub_f8cd {
  strings:
    $key_f8cd = { ac a5 [2] d8 bd [2] 9f bf [2] d8 ae [2] 96 a2 [2] 9a a8 [2] 8d a3 [2] 96 ed [2] ab }

  condition:
    any of them
}