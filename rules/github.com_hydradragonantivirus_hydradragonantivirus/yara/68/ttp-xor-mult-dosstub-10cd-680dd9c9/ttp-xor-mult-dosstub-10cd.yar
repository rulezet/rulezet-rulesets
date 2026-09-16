rule TTP_XOR_MULT_DOSStub_10cd {
  strings:
    $key_10cd = { 44 a5 [2] 30 bd [2] 77 bf [2] 30 ae [2] 7e a2 [2] 72 a8 [2] 65 a3 [2] 7e ed [2] 43 }

  condition:
    any of them
}