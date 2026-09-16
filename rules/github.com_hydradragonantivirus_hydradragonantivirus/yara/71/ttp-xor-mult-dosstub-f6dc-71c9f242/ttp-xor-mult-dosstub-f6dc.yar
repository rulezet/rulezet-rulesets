rule TTP_XOR_MULT_DOSStub_f6dc {
  strings:
    $key_f6dc = { a2 b4 [2] d6 ac [2] 91 ae [2] d6 bf [2] 98 b3 [2] 94 b9 [2] 83 b2 [2] 98 fc [2] a5 }

  condition:
    any of them
}