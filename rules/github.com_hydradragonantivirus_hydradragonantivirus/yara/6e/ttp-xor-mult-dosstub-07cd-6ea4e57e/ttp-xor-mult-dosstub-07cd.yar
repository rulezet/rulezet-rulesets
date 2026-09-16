rule TTP_XOR_MULT_DOSStub_07cd {
  strings:
    $key_07cd = { 53 a5 [2] 27 bd [2] 60 bf [2] 27 ae [2] 69 a2 [2] 65 a8 [2] 72 a3 [2] 69 ed [2] 54 }

  condition:
    any of them
}