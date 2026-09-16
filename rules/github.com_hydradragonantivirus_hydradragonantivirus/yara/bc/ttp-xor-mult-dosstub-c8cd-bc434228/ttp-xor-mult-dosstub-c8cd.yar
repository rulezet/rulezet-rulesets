rule TTP_XOR_MULT_DOSStub_c8cd {
  strings:
    $key_c8cd = { 9c a5 [2] e8 bd [2] af bf [2] e8 ae [2] a6 a2 [2] aa a8 [2] bd a3 [2] a6 ed [2] 9b }

  condition:
    any of them
}