rule TTP_XOR_MULT_DOSStub_09cd {
  strings:
    $key_09cd = { 5d a5 [2] 29 bd [2] 6e bf [2] 29 ae [2] 67 a2 [2] 6b a8 [2] 7c a3 [2] 67 ed [2] 5a }

  condition:
    any of them
}