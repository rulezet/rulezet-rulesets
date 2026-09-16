rule TTP_XOR_MULT_DOSStub_48ef {
  strings:
    $key_48ef = { 1c 87 [2] 68 9f [2] 2f 9d [2] 68 8c [2] 26 80 [2] 2a 8a [2] 3d 81 [2] 26 cf [2] 1b }

  condition:
    any of them
}