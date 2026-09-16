rule TTP_XOR_MULT_DOSStub_ffdc {
  strings:
    $key_ffdc = { ab b4 [2] df ac [2] 98 ae [2] df bf [2] 91 b3 [2] 9d b9 [2] 8a b2 [2] 91 fc [2] ac }

  condition:
    any of them
}