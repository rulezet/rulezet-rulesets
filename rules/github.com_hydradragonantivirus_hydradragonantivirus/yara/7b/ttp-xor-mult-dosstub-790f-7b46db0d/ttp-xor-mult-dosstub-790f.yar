rule TTP_XOR_MULT_DOSStub_790f {
  strings:
    $key_790f = { 2d 67 [2] 59 7f [2] 1e 7d [2] 59 6c [2] 17 60 [2] 1b 6a [2] 0c 61 [2] 17 2f [2] 2a }

  condition:
    any of them
}