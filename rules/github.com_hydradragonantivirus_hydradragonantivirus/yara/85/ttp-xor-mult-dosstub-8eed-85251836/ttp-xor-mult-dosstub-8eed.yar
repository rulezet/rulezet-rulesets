rule TTP_XOR_MULT_DOSStub_8eed {
  strings:
    $key_8eed = { da 85 [2] ae 9d [2] e9 9f [2] ae 8e [2] e0 82 [2] ec 88 [2] fb 83 [2] e0 cd [2] dd }

  condition:
    any of them
}