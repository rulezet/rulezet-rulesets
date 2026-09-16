rule TTP_XOR_MULT_DOSStub_c9cd {
  strings:
    $key_c9cd = { 9d a5 [2] e9 bd [2] ae bf [2] e9 ae [2] a7 a2 [2] ab a8 [2] bc a3 [2] a7 ed [2] 9a }

  condition:
    any of them
}