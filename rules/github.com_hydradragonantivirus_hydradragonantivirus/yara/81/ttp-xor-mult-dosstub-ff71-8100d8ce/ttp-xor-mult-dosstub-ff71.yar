rule TTP_XOR_MULT_DOSStub_ff71 {
  strings:
    $key_ff71 = { ab 19 [2] df 01 [2] 98 03 [2] df 12 [2] 91 1e [2] 9d 14 [2] 8a 1f [2] 91 51 [2] ac }

  condition:
    any of them
}