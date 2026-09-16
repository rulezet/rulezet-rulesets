rule TTP_XOR_MULT_DOSStub_ea9d {
  strings:
    $key_ea9d = { be f5 [2] ca ed [2] 8d ef [2] ca fe [2] 84 f2 [2] 88 f8 [2] 9f f3 [2] 84 bd [2] b9 }

  condition:
    any of them
}