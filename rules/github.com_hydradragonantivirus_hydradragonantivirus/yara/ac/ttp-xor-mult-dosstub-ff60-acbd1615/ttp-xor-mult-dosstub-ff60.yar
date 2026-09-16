rule TTP_XOR_MULT_DOSStub_ff60 {
  strings:
    $key_ff60 = { ab 08 [2] df 10 [2] 98 12 [2] df 03 [2] 91 0f [2] 9d 05 [2] 8a 0e [2] 91 40 [2] ac }

  condition:
    any of them
}