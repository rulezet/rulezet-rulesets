rule TTP_XOR_MULT_DOSStub_8e2f {
  strings:
    $key_8e2f = { da 47 [2] ae 5f [2] e9 5d [2] ae 4c [2] e0 40 [2] ec 4a [2] fb 41 [2] e0 0f [2] dd }

  condition:
    any of them
}