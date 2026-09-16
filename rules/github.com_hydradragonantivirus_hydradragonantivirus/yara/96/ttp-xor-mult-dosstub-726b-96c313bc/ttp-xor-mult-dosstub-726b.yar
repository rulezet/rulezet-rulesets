rule TTP_XOR_MULT_DOSStub_726b {
  strings:
    $key_726b = { 26 03 [2] 52 1b [2] 15 19 [2] 52 08 [2] 1c 04 [2] 10 0e [2] 07 05 [2] 1c 4b [2] 21 }

  condition:
    any of them
}