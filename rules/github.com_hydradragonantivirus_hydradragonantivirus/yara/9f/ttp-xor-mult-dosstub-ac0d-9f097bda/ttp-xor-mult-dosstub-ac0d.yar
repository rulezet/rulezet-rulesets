rule TTP_XOR_MULT_DOSStub_ac0d {
  strings:
    $key_ac0d = { f8 65 [2] 8c 7d [2] cb 7f [2] 8c 6e [2] c2 62 [2] ce 68 [2] d9 63 [2] c2 2d [2] ff }

  condition:
    any of them
}