rule TTP_XOR_MULT_DOSStub_6afe {
  strings:
    $key_6afe = { 3e 96 [2] 4a 8e [2] 0d 8c [2] 4a 9d [2] 04 91 [2] 08 9b [2] 1f 90 [2] 04 de [2] 39 }

  condition:
    any of them
}