rule TTP_XOR_MULT_DOSStub_296b {
  strings:
    $key_296b = { 7d 03 [2] 09 1b [2] 4e 19 [2] 09 08 [2] 47 04 [2] 4b 0e [2] 5c 05 [2] 47 4b [2] 7a }

  condition:
    any of them
}