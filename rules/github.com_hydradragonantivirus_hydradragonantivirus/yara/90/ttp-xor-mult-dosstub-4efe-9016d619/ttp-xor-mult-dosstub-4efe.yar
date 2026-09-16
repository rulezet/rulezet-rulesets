rule TTP_XOR_MULT_DOSStub_4efe {
  strings:
    $key_4efe = { 1a 96 [2] 6e 8e [2] 29 8c [2] 6e 9d [2] 20 91 [2] 2c 9b [2] 3b 90 [2] 20 de [2] 1d }

  condition:
    any of them
}