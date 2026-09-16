rule TTP_XOR_MULT_DOSStub_ff7f {
  strings:
    $key_ff7f = { ab 17 [2] df 0f [2] 98 0d [2] df 1c [2] 91 10 [2] 9d 1a [2] 8a 11 [2] 91 5f [2] ac }

  condition:
    any of them
}