rule TTP_XOR_MULT_DOSStub_8aef {
  strings:
    $key_8aef = { de 87 [2] aa 9f [2] ed 9d [2] aa 8c [2] e4 80 [2] e8 8a [2] ff 81 [2] e4 cf [2] d9 }

  condition:
    any of them
}