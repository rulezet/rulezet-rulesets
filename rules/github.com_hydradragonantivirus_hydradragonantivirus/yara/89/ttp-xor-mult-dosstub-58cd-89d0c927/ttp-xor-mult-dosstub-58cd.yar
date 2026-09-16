rule TTP_XOR_MULT_DOSStub_58cd {
  strings:
    $key_58cd = { 0c a5 [2] 78 bd [2] 3f bf [2] 78 ae [2] 36 a2 [2] 3a a8 [2] 2d a3 [2] 36 ed [2] 0b }

  condition:
    any of them
}