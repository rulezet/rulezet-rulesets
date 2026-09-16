rule TTP_XOR_MULT_DOSStub_282b {
  strings:
    $key_282b = { 7c 43 [2] 08 5b [2] 4f 59 [2] 08 48 [2] 46 44 [2] 4a 4e [2] 5d 45 [2] 46 0b [2] 7b }

  condition:
    any of them
}