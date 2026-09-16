rule TTP_XOR_MULT_DOSStub_ff23 {
  strings:
    $key_ff23 = { ab 4b [2] df 53 [2] 98 51 [2] df 40 [2] 91 4c [2] 9d 46 [2] 8a 4d [2] 91 03 [2] ac }

  condition:
    any of them
}