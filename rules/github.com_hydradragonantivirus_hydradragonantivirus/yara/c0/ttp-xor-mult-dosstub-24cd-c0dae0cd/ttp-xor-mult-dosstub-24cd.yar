rule TTP_XOR_MULT_DOSStub_24cd {
  strings:
    $key_24cd = { 70 a5 [2] 04 bd [2] 43 bf [2] 04 ae [2] 4a a2 [2] 46 a8 [2] 51 a3 [2] 4a ed [2] 77 }

  condition:
    any of them
}