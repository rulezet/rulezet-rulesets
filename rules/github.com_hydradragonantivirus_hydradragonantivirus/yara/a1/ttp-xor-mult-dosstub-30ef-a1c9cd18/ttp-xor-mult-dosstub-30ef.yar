rule TTP_XOR_MULT_DOSStub_30ef {
  strings:
    $key_30ef = { 64 87 [2] 10 9f [2] 57 9d [2] 10 8c [2] 5e 80 [2] 52 8a [2] 45 81 [2] 5e cf [2] 63 }

  condition:
    any of them
}