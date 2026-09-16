rule TTP_XOR_MULT_DOSStub_ffe8 {
  strings:
    $key_ffe8 = { ab 80 [2] df 98 [2] 98 9a [2] df 8b [2] 91 87 [2] 9d 8d [2] 8a 86 [2] 91 c8 [2] ac }

  condition:
    any of them
}