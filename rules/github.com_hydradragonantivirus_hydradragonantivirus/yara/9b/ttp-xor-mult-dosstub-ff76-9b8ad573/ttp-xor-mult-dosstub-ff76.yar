rule TTP_XOR_MULT_DOSStub_ff76 {
  strings:
    $key_ff76 = { ab 1e [2] df 06 [2] 98 04 [2] df 15 [2] 91 19 [2] 9d 13 [2] 8a 18 [2] 91 56 [2] ac }

  condition:
    any of them
}