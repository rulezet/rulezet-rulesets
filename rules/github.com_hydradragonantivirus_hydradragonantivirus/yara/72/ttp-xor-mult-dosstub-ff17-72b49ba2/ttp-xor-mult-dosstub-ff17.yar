rule TTP_XOR_MULT_DOSStub_ff17 {
  strings:
    $key_ff17 = { ab 7f [2] df 67 [2] 98 65 [2] df 74 [2] 91 78 [2] 9d 72 [2] 8a 79 [2] 91 37 [2] ac }

  condition:
    any of them
}