rule TTP_XOR_MULT_DOSStub_ff13 {
  strings:
    $key_ff13 = { ab 7b [2] df 63 [2] 98 61 [2] df 70 [2] 91 7c [2] 9d 76 [2] 8a 7d [2] 91 33 [2] ac }

  condition:
    any of them
}