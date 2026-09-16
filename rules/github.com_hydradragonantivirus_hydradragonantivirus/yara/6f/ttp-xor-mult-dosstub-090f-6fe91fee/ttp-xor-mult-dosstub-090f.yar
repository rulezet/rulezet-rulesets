rule TTP_XOR_MULT_DOSStub_090f {
  strings:
    $key_090f = { 5d 67 [2] 29 7f [2] 6e 7d [2] 29 6c [2] 67 60 [2] 6b 6a [2] 7c 61 [2] 67 2f [2] 5a }

  condition:
    any of them
}