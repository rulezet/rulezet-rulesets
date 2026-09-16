rule TTP_XOR_MULT_DOSStub_8eef {
  strings:
    $key_8eef = { da 87 [2] ae 9f [2] e9 9d [2] ae 8c [2] e0 80 [2] ec 8a [2] fb 81 [2] e0 cf [2] dd }

  condition:
    any of them
}