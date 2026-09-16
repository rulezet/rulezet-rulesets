rule TTP_XOR_MULT_DOSStub_ff8a {
  strings:
    $key_ff8a = { ab e2 [2] df fa [2] 98 f8 [2] df e9 [2] 91 e5 [2] 9d ef [2] 8a e4 [2] 91 aa [2] ac }

  condition:
    any of them
}