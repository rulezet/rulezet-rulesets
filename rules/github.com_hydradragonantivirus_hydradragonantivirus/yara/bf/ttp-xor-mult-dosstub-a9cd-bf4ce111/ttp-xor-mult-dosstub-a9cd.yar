rule TTP_XOR_MULT_DOSStub_a9cd {
  strings:
    $key_a9cd = { fd a5 [2] 89 bd [2] ce bf [2] 89 ae [2] c7 a2 [2] cb a8 [2] dc a3 [2] c7 ed [2] fa }

  condition:
    any of them
}