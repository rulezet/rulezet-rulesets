rule TTP_XOR_MULT_DOSStub_ffe4 {
  strings:
    $key_ffe4 = { ab 8c [2] df 94 [2] 98 96 [2] df 87 [2] 91 8b [2] 9d 81 [2] 8a 8a [2] 91 c4 [2] ac }

  condition:
    any of them
}