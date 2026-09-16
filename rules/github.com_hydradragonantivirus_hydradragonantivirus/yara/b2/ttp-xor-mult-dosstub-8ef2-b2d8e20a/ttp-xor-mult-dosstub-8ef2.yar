rule TTP_XOR_MULT_DOSStub_8ef2 {
  strings:
    $key_8ef2 = { da 9a [2] ae 82 [2] e9 80 [2] ae 91 [2] e0 9d [2] ec 97 [2] fb 9c [2] e0 d2 [2] dd }

  condition:
    any of them
}