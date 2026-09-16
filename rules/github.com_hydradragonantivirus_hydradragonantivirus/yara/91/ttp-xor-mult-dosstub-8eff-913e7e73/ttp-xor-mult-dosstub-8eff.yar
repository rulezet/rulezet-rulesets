rule TTP_XOR_MULT_DOSStub_8eff {
  strings:
    $key_8eff = { da 97 [2] ae 8f [2] e9 8d [2] ae 9c [2] e0 90 [2] ec 9a [2] fb 91 [2] e0 df [2] dd }

  condition:
    any of them
}