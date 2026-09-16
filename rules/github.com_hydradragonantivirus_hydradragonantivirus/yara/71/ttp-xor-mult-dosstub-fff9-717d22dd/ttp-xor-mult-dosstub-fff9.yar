rule TTP_XOR_MULT_DOSStub_fff9 {
  strings:
    $key_fff9 = { ab 91 [2] df 89 [2] 98 8b [2] df 9a [2] 91 96 [2] 9d 9c [2] 8a 97 [2] 91 d9 [2] ac }

  condition:
    any of them
}