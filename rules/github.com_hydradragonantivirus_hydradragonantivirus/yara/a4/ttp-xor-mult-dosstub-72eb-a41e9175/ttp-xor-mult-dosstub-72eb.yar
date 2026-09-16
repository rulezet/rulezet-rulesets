rule TTP_XOR_MULT_DOSStub_72eb {
  strings:
    $key_72eb = { 26 83 [2] 52 9b [2] 15 99 [2] 52 88 [2] 1c 84 [2] 10 8e [2] 07 85 [2] 1c cb [2] 21 }

  condition:
    any of them
}