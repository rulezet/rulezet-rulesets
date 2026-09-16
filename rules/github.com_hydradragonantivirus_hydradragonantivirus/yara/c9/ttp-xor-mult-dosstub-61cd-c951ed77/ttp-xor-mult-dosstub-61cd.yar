rule TTP_XOR_MULT_DOSStub_61cd {
  strings:
    $key_61cd = { 35 a5 [2] 41 bd [2] 06 bf [2] 41 ae [2] 0f a2 [2] 03 a8 [2] 14 a3 [2] 0f ed [2] 32 }

  condition:
    any of them
}