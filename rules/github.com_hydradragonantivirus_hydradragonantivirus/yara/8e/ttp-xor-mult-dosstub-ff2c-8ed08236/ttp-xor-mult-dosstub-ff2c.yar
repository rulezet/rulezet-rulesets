rule TTP_XOR_MULT_DOSStub_ff2c {
  strings:
    $key_ff2c = { ab 44 [2] df 5c [2] 98 5e [2] df 4f [2] 91 43 [2] 9d 49 [2] 8a 42 [2] 91 0c [2] ac }

  condition:
    any of them
}