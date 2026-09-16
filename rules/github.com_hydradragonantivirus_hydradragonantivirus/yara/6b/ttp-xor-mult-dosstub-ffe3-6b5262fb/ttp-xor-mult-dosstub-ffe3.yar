rule TTP_XOR_MULT_DOSStub_ffe3 {
  strings:
    $key_ffe3 = { ab 8b [2] df 93 [2] 98 91 [2] df 80 [2] 91 8c [2] 9d 86 [2] 8a 8d [2] 91 c3 [2] ac }

  condition:
    any of them
}