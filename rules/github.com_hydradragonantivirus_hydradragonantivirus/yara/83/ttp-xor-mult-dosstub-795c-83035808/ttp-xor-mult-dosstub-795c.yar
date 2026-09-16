rule TTP_XOR_MULT_DOSStub_795c {
  strings:
    $key_795c = { 2d 34 [2] 59 2c [2] 1e 2e [2] 59 3f [2] 17 33 [2] 1b 39 [2] 0c 32 [2] 17 7c [2] 2a }

  condition:
    any of them
}