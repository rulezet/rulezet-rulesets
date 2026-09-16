rule TTP_XOR_MULT_DOSStub_ffea {
  strings:
    $key_ffea = { ab 82 [2] df 9a [2] 98 98 [2] df 89 [2] 91 85 [2] 9d 8f [2] 8a 84 [2] 91 ca [2] ac }

  condition:
    any of them
}