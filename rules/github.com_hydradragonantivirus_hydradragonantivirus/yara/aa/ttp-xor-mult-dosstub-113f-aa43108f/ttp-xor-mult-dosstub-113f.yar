rule TTP_XOR_MULT_DOSStub_113f {
  strings:
    $key_113f = { 45 57 [2] 31 4f [2] 76 4d [2] 31 5c [2] 7f 50 [2] 73 5a [2] 64 51 [2] 7f 1f [2] 42 }

  condition:
    any of them
}