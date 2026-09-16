rule TTP_XOR_MULT_DOSStub_097b {
  strings:
    $key_097b = { 5d 13 [2] 29 0b [2] 6e 09 [2] 29 18 [2] 67 14 [2] 6b 1e [2] 7c 15 [2] 67 5b [2] 5a }

  condition:
    any of them
}