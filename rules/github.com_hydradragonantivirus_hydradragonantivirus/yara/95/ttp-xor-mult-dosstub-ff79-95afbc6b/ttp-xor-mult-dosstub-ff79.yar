rule TTP_XOR_MULT_DOSStub_ff79 {
  strings:
    $key_ff79 = { ab 11 [2] df 09 [2] 98 0b [2] df 1a [2] 91 16 [2] 9d 1c [2] 8a 17 [2] 91 59 [2] ac }

  condition:
    any of them
}