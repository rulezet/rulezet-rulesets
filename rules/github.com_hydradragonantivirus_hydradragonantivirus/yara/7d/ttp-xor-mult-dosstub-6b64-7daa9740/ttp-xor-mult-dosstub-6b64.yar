rule TTP_XOR_MULT_DOSStub_6b64 {
  strings:
    $key_6b64 = { 3f 0c [2] 4b 14 [2] 0c 16 [2] 4b 07 [2] 05 0b [2] 09 01 [2] 1e 0a [2] 05 44 [2] 38 }

  condition:
    any of them
}