rule TTP_XOR_MULT_DOSStub_63cd {
  strings:
    $key_63cd = { 37 a5 [2] 43 bd [2] 04 bf [2] 43 ae [2] 0d a2 [2] 01 a8 [2] 16 a3 [2] 0d ed [2] 30 }

  condition:
    any of them
}