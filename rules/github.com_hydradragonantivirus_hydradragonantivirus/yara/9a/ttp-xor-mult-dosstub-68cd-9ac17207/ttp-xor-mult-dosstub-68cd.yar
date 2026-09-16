rule TTP_XOR_MULT_DOSStub_68cd {
  strings:
    $key_68cd = { 3c a5 [2] 48 bd [2] 0f bf [2] 48 ae [2] 06 a2 [2] 0a a8 [2] 1d a3 [2] 06 ed [2] 3b }

  condition:
    any of them
}