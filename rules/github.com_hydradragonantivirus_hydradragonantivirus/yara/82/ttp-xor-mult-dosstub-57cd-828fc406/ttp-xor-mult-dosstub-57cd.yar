rule TTP_XOR_MULT_DOSStub_57cd {
  strings:
    $key_57cd = { 03 a5 [2] 77 bd [2] 30 bf [2] 77 ae [2] 39 a2 [2] 35 a8 [2] 22 a3 [2] 39 ed [2] 04 }

  condition:
    any of them
}