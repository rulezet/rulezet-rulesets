rule TTP_XOR_MULT_DOSStub_ff28 {
  strings:
    $key_ff28 = { ab 40 [2] df 58 [2] 98 5a [2] df 4b [2] 91 47 [2] 9d 4d [2] 8a 46 [2] 91 08 [2] ac }

  condition:
    any of them
}