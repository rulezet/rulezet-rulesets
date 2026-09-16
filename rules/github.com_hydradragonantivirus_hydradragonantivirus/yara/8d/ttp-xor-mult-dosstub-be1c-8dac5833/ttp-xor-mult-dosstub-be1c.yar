rule TTP_XOR_MULT_DOSStub_be1c {
  strings:
    $key_be1c = { ea 74 [2] 9e 6c [2] d9 6e [2] 9e 7f [2] d0 73 [2] dc 79 [2] cb 72 [2] d0 3c [2] ed }

  condition:
    any of them
}