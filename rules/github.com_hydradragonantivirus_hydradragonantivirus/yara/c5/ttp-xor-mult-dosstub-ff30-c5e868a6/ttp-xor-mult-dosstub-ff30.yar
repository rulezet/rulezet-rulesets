rule TTP_XOR_MULT_DOSStub_ff30 {
  strings:
    $key_ff30 = { ab 58 [2] df 40 [2] 98 42 [2] df 53 [2] 91 5f [2] 9d 55 [2] 8a 5e [2] 91 10 [2] ac }

  condition:
    any of them
}