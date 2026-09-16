rule TTP_XOR_MULT_DOSStub_3cef {
  strings:
    $key_3cef = { 68 87 [2] 1c 9f [2] 5b 9d [2] 1c 8c [2] 52 80 [2] 5e 8a [2] 49 81 [2] 52 cf [2] 6f }

  condition:
    any of them
}