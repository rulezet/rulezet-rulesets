rule TTP_XOR_MULT_DOSStub_30cd {
  strings:
    $key_30cd = { 64 a5 [2] 10 bd [2] 57 bf [2] 10 ae [2] 5e a2 [2] 52 a8 [2] 45 a3 [2] 5e ed [2] 63 }

  condition:
    any of them
}