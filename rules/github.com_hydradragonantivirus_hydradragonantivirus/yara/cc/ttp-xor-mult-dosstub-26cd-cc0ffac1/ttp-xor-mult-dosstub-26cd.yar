rule TTP_XOR_MULT_DOSStub_26cd {
  strings:
    $key_26cd = { 72 a5 [2] 06 bd [2] 41 bf [2] 06 ae [2] 48 a2 [2] 44 a8 [2] 53 a3 [2] 48 ed [2] 75 }

  condition:
    any of them
}