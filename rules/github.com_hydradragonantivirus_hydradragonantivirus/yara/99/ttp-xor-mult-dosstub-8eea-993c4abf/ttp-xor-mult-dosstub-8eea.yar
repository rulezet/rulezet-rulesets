rule TTP_XOR_MULT_DOSStub_8eea {
  strings:
    $key_8eea = { da 82 [2] ae 9a [2] e9 98 [2] ae 89 [2] e0 85 [2] ec 8f [2] fb 84 [2] e0 ca [2] dd }

  condition:
    any of them
}