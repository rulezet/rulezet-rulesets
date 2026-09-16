rule TTP_XOR_MULT_DOSStub_ffdf {
  strings:
    $key_ffdf = { ab b7 [2] df af [2] 98 ad [2] df bc [2] 91 b0 [2] 9d ba [2] 8a b1 [2] 91 ff [2] ac }

  condition:
    any of them
}