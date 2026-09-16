rule TTP_XOR_MULT_DOSStub_ddcc {
  strings:
    $key_ddcc = { 89 a4 [2] fd bc [2] ba be [2] fd af [2] b3 a3 [2] bf a9 [2] a8 a2 [2] b3 ec [2] 8e }

  condition:
    any of them
}