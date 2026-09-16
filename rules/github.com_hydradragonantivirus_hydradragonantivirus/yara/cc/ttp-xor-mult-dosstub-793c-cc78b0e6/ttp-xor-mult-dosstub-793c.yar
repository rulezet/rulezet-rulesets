rule TTP_XOR_MULT_DOSStub_793c {
  strings:
    $key_793c = { 2d 54 [2] 59 4c [2] 1e 4e [2] 59 5f [2] 17 53 [2] 1b 59 [2] 0c 52 [2] 17 1c [2] 2a }

  condition:
    any of them
}