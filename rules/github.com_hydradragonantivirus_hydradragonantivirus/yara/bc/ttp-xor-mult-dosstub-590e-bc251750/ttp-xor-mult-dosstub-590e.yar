rule TTP_XOR_MULT_DOSStub_590e {
  strings:
    $key_590e = { 0d 66 [2] 79 7e [2] 3e 7c [2] 79 6d [2] 37 61 [2] 3b 6b [2] 2c 60 [2] 37 2e [2] 0a }

  condition:
    any of them
}