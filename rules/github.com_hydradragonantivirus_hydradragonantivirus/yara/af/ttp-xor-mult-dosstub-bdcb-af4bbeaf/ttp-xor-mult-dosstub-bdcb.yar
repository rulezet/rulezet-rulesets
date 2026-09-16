rule TTP_XOR_MULT_DOSStub_bdcb {
  strings:
    $key_bdcb = { e9 a3 [2] 9d bb [2] da b9 [2] 9d a8 [2] d3 a4 [2] df ae [2] c8 a5 [2] d3 eb [2] ee }

  condition:
    any of them
}