rule TTP_XOR_MULT_DOSStub_c3cd {
  strings:
    $key_c3cd = { 97 a5 [2] e3 bd [2] a4 bf [2] e3 ae [2] ad a2 [2] a1 a8 [2] b6 a3 [2] ad ed [2] 90 }

  condition:
    any of them
}