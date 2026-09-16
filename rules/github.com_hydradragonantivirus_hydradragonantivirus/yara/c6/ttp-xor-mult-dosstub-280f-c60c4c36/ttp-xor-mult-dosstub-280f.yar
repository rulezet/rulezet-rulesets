rule TTP_XOR_MULT_DOSStub_280f {
  strings:
    $key_280f = { 7c 67 [2] 08 7f [2] 4f 7d [2] 08 6c [2] 46 60 [2] 4a 6a [2] 5d 61 [2] 46 2f [2] 7b }

  condition:
    any of them
}