rule TTP_XOR_MULT_DOSStub_21cd {
  strings:
    $key_21cd = { 75 a5 [2] 01 bd [2] 46 bf [2] 01 ae [2] 4f a2 [2] 43 a8 [2] 54 a3 [2] 4f ed [2] 72 }

  condition:
    any of them
}