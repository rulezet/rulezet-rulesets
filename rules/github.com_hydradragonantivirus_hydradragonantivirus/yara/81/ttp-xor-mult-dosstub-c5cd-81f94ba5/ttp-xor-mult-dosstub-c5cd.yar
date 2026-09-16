rule TTP_XOR_MULT_DOSStub_c5cd {
  strings:
    $key_c5cd = { 91 a5 [2] e5 bd [2] a2 bf [2] e5 ae [2] ab a2 [2] a7 a8 [2] b0 a3 [2] ab ed [2] 96 }

  condition:
    any of them
}