rule TTP_XOR_MULT_DOSStub_ff5c {
  strings:
    $key_ff5c = { ab 34 [2] df 2c [2] 98 2e [2] df 3f [2] 91 33 [2] 9d 39 [2] 8a 32 [2] 91 7c [2] ac }

  condition:
    any of them
}