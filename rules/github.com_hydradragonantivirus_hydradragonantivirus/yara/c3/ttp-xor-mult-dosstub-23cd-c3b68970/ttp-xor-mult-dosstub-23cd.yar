rule TTP_XOR_MULT_DOSStub_23cd {
  strings:
    $key_23cd = { 77 a5 [2] 03 bd [2] 44 bf [2] 03 ae [2] 4d a2 [2] 41 a8 [2] 56 a3 [2] 4d ed [2] 70 }

  condition:
    any of them
}