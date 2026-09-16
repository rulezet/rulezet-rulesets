rule TTP_XOR_MULT_DOSStub_06cd {
  strings:
    $key_06cd = { 52 a5 [2] 26 bd [2] 61 bf [2] 26 ae [2] 68 a2 [2] 64 a8 [2] 73 a3 [2] 68 ed [2] 55 }

  condition:
    any of them
}