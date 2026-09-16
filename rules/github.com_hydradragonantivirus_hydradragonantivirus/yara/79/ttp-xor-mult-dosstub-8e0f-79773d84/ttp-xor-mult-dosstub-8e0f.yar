rule TTP_XOR_MULT_DOSStub_8e0f {
  strings:
    $key_8e0f = { da 67 [2] ae 7f [2] e9 7d [2] ae 6c [2] e0 60 [2] ec 6a [2] fb 61 [2] e0 2f [2] dd }

  condition:
    any of them
}