rule TTP_XOR_MULT_DOSStub_15cd {
  strings:
    $key_15cd = { 41 a5 [2] 35 bd [2] 72 bf [2] 35 ae [2] 7b a2 [2] 77 a8 [2] 60 a3 [2] 7b ed [2] 46 }

  condition:
    any of them
}