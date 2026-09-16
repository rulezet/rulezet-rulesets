rule TTP_XOR_MULT_DOSStub_27cd {
  strings:
    $key_27cd = { 73 a5 [2] 07 bd [2] 40 bf [2] 07 ae [2] 49 a2 [2] 45 a8 [2] 52 a3 [2] 49 ed [2] 74 }

  condition:
    any of them
}