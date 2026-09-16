rule TTP_XOR_MULT_DOSStub_ff50 {
  strings:
    $key_ff50 = { ab 38 [2] df 20 [2] 98 22 [2] df 33 [2] 91 3f [2] 9d 35 [2] 8a 3e [2] 91 70 [2] ac }

  condition:
    any of them
}