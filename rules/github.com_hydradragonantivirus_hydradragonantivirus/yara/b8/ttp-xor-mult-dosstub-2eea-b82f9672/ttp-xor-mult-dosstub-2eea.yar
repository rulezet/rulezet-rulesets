rule TTP_XOR_MULT_DOSStub_2eea {
  strings:
    $key_2eea = { 7a 82 [2] 0e 9a [2] 49 98 [2] 0e 89 [2] 40 85 [2] 4c 8f [2] 5b 84 [2] 40 ca [2] 7d }

  condition:
    any of them
}