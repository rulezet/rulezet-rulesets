rule TTP_XOR_MULT_DOSStub_65cd {
  strings:
    $key_65cd = { 31 a5 [2] 45 bd [2] 02 bf [2] 45 ae [2] 0b a2 [2] 07 a8 [2] 10 a3 [2] 0b ed [2] 36 }

  condition:
    any of them
}