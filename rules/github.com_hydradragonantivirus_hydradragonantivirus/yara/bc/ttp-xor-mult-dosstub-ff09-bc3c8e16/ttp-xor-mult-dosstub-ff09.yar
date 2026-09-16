rule TTP_XOR_MULT_DOSStub_ff09 {
  strings:
    $key_ff09 = { ab 61 [2] df 79 [2] 98 7b [2] df 6a [2] 91 66 [2] 9d 6c [2] 8a 67 [2] 91 29 [2] ac }

  condition:
    any of them
}