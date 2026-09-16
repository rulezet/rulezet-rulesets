rule TTP_XOR_MULT_DOSStub_ff55 {
  strings:
    $key_ff55 = { ab 3d [2] df 25 [2] 98 27 [2] df 36 [2] 91 3a [2] 9d 30 [2] 8a 3b [2] 91 75 [2] ac }

  condition:
    any of them
}