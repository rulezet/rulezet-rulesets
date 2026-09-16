rule TTP_XOR_MULT_DOSStub_7902 {
  strings:
    $key_7902 = { 2d 6a [2] 59 72 [2] 1e 70 [2] 59 61 [2] 17 6d [2] 1b 67 [2] 0c 6c [2] 17 22 [2] 2a }

  condition:
    any of them
}