rule TTP_XOR_MULT_DOSStub_ff6b {
  strings:
    $key_ff6b = { ab 03 [2] df 1b [2] 98 19 [2] df 08 [2] 91 04 [2] 9d 0e [2] 8a 05 [2] 91 4b [2] ac }

  condition:
    any of them
}