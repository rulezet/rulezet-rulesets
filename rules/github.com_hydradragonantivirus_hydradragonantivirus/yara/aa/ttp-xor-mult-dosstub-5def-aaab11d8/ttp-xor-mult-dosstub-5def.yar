rule TTP_XOR_MULT_DOSStub_5def {
  strings:
    $key_5def = { 09 87 [2] 7d 9f [2] 3a 9d [2] 7d 8c [2] 33 80 [2] 3f 8a [2] 28 81 [2] 33 cf [2] 0e }

  condition:
    any of them
}