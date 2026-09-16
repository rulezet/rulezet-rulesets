rule TTP_XOR_MULT_DOSStub_ff8e {
  strings:
    $key_ff8e = { ab e6 [2] df fe [2] 98 fc [2] df ed [2] 91 e1 [2] 9d eb [2] 8a e0 [2] 91 ae [2] ac }

  condition:
    any of them
}