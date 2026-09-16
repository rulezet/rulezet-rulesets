rule TTP_XOR_MULT_DOSStub_ff29 {
  strings:
    $key_ff29 = { ab 41 [2] df 59 [2] 98 5b [2] df 4a [2] 91 46 [2] 9d 4c [2] 8a 47 [2] 91 09 [2] ac }

  condition:
    any of them
}