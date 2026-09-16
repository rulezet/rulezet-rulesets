rule TTP_XOR_MULT_DOSStub_ff3e {
  strings:
    $key_ff3e = { ab 56 [2] df 4e [2] 98 4c [2] df 5d [2] 91 51 [2] 9d 5b [2] 8a 50 [2] 91 1e [2] ac }

  condition:
    any of them
}