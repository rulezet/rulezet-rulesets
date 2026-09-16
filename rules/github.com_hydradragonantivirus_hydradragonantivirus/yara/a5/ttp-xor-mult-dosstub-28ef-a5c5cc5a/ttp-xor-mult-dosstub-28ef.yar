rule TTP_XOR_MULT_DOSStub_28ef {
  strings:
    $key_28ef = { 7c 87 [2] 08 9f [2] 4f 9d [2] 08 8c [2] 46 80 [2] 4a 8a [2] 5d 81 [2] 46 cf [2] 7b }

  condition:
    any of them
}