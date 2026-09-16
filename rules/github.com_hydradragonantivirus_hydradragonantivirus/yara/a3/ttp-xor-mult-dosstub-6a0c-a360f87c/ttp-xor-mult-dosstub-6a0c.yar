rule TTP_XOR_MULT_DOSStub_6a0c {
  strings:
    $key_6a0c = { 3e 64 [2] 4a 7c [2] 0d 7e [2] 4a 6f [2] 04 63 [2] 08 69 [2] 1f 62 [2] 04 2c [2] 39 }

  condition:
    any of them
}