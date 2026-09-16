rule TTP_XOR_MULT_DOSStub_01cd {
  strings:
    $key_01cd = { 55 a5 [2] 21 bd [2] 66 bf [2] 21 ae [2] 6f a2 [2] 63 a8 [2] 74 a3 [2] 6f ed [2] 52 }

  condition:
    any of them
}