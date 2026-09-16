rule TTP_XOR_MULT_DOSStub_1eea {
  strings:
    $key_1eea = { 4a 82 [2] 3e 9a [2] 79 98 [2] 3e 89 [2] 70 85 [2] 7c 8f [2] 6b 84 [2] 70 ca [2] 4d }

  condition:
    any of them
}