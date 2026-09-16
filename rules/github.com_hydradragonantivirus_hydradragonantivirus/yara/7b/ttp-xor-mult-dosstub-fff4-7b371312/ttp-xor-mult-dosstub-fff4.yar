rule TTP_XOR_MULT_DOSStub_fff4 {
  strings:
    $key_fff4 = { ab 9c [2] df 84 [2] 98 86 [2] df 97 [2] 91 9b [2] 9d 91 [2] 8a 9a [2] 91 d4 [2] ac }

  condition:
    any of them
}