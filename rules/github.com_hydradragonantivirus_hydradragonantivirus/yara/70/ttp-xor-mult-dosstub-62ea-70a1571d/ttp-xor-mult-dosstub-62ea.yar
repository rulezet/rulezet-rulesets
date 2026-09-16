rule TTP_XOR_MULT_DOSStub_62ea {
  strings:
    $key_62ea = { 36 82 [2] 42 9a [2] 05 98 [2] 42 89 [2] 0c 85 [2] 00 8f [2] 17 84 [2] 0c ca [2] 31 }

  condition:
    any of them
}