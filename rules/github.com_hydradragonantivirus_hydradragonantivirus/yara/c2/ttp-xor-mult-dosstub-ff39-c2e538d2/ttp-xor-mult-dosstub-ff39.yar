rule TTP_XOR_MULT_DOSStub_ff39 {
  strings:
    $key_ff39 = { ab 51 [2] df 49 [2] 98 4b [2] df 5a [2] 91 56 [2] 9d 5c [2] 8a 57 [2] 91 19 [2] ac }

  condition:
    any of them
}