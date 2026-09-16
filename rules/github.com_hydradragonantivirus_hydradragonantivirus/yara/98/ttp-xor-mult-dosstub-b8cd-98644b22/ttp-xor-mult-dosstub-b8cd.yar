rule TTP_XOR_MULT_DOSStub_b8cd {
  strings:
    $key_b8cd = { ec a5 [2] 98 bd [2] df bf [2] 98 ae [2] d6 a2 [2] da a8 [2] cd a3 [2] d6 ed [2] eb }

  condition:
    any of them
}