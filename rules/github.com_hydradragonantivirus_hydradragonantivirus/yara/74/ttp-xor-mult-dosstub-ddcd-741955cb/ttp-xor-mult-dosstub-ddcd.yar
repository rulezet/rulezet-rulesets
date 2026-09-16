rule TTP_XOR_MULT_DOSStub_ddcd {
  strings:
    $key_ddcd = { 89 a5 [2] fd bd [2] ba bf [2] fd ae [2] b3 a2 [2] bf a8 [2] a8 a3 [2] b3 ed [2] 8e }

  condition:
    any of them
}