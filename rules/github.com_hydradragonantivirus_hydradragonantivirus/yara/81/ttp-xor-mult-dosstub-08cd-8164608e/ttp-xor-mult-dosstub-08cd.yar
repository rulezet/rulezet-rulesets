rule TTP_XOR_MULT_DOSStub_08cd {
  strings:
    $key_08cd = { 5c a5 [2] 28 bd [2] 6f bf [2] 28 ae [2] 66 a2 [2] 6a a8 [2] 7d a3 [2] 66 ed [2] 5b }

  condition:
    any of them
}