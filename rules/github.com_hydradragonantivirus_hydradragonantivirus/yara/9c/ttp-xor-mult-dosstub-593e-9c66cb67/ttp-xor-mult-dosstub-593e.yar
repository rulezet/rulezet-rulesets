rule TTP_XOR_MULT_DOSStub_593e {
  strings:
    $key_593e = { 0d 56 [2] 79 4e [2] 3e 4c [2] 79 5d [2] 37 51 [2] 3b 5b [2] 2c 50 [2] 37 1e [2] 0a }

  condition:
    any of them
}