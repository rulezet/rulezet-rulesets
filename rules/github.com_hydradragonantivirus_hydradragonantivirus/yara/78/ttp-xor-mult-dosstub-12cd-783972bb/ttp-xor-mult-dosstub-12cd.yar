rule TTP_XOR_MULT_DOSStub_12cd {
  strings:
    $key_12cd = { 46 a5 [2] 32 bd [2] 75 bf [2] 32 ae [2] 7c a2 [2] 70 a8 [2] 67 a3 [2] 7c ed [2] 41 }

  condition:
    any of them
}