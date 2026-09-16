rule TTP_XOR_MULT_DOSStub_f3cd {
  strings:
    $key_f3cd = { a7 a5 [2] d3 bd [2] 94 bf [2] d3 ae [2] 9d a2 [2] 91 a8 [2] 86 a3 [2] 9d ed [2] a0 }

  condition:
    any of them
}