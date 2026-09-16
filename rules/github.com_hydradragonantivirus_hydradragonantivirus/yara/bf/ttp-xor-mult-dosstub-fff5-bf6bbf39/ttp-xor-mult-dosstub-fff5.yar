rule TTP_XOR_MULT_DOSStub_fff5 {
  strings:
    $key_fff5 = { ab 9d [2] df 85 [2] 98 87 [2] df 96 [2] 91 9a [2] 9d 90 [2] 8a 9b [2] 91 d5 [2] ac }

  condition:
    any of them
}