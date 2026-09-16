rule TTP_XOR_MULT_DOSStub_c2cd {
  strings:
    $key_c2cd = { 96 a5 [2] e2 bd [2] a5 bf [2] e2 ae [2] ac a2 [2] a0 a8 [2] b7 a3 [2] ac ed [2] 91 }

  condition:
    any of them
}