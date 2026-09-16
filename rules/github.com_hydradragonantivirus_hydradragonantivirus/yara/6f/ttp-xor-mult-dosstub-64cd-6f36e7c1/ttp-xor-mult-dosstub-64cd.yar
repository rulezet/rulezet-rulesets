rule TTP_XOR_MULT_DOSStub_64cd {
  strings:
    $key_64cd = { 30 a5 [2] 44 bd [2] 03 bf [2] 44 ae [2] 0a a2 [2] 06 a8 [2] 11 a3 [2] 0a ed [2] 37 }

  condition:
    any of them
}