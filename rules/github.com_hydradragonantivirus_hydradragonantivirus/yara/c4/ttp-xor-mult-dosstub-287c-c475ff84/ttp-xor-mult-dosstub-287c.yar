rule TTP_XOR_MULT_DOSStub_287c {
  strings:
    $key_287c = { 7c 14 [2] 08 0c [2] 4f 0e [2] 08 1f [2] 46 13 [2] 4a 19 [2] 5d 12 [2] 46 5c [2] 7b }

  condition:
    any of them
}