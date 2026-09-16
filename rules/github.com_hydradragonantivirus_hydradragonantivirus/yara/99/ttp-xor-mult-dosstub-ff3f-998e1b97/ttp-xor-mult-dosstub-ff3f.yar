rule TTP_XOR_MULT_DOSStub_ff3f {
  strings:
    $key_ff3f = { ab 57 [2] df 4f [2] 98 4d [2] df 5c [2] 91 50 [2] 9d 5a [2] 8a 51 [2] 91 1f [2] ac }

  condition:
    any of them
}