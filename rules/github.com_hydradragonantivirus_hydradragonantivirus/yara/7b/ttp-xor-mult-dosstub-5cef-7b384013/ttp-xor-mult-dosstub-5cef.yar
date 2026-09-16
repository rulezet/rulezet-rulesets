rule TTP_XOR_MULT_DOSStub_5cef {
  strings:
    $key_5cef = { 08 87 [2] 7c 9f [2] 3b 9d [2] 7c 8c [2] 32 80 [2] 3e 8a [2] 29 81 [2] 32 cf [2] 0f }

  condition:
    any of them
}