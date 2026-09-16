rule TTP_XOR_MULT_DOSStub_096b {
  strings:
    $key_096b = { 5d 03 [2] 29 1b [2] 6e 19 [2] 29 08 [2] 67 04 [2] 6b 0e [2] 7c 05 [2] 67 4b [2] 5a }

  condition:
    any of them
}