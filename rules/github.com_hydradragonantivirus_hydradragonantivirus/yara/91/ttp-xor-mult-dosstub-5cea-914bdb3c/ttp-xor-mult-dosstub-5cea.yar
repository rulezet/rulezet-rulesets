rule TTP_XOR_MULT_DOSStub_5cea {
  strings:
    $key_5cea = { 08 82 [2] 7c 9a [2] 3b 98 [2] 7c 89 [2] 32 85 [2] 3e 8f [2] 29 84 [2] 32 ca [2] 0f }

  condition:
    any of them
}