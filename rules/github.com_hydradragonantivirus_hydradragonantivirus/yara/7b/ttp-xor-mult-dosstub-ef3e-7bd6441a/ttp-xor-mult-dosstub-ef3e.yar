rule TTP_XOR_MULT_DOSStub_ef3e {
  strings:
    $key_ef3e = { bb 56 [2] cf 4e [2] 88 4c [2] cf 5d [2] 81 51 [2] 8d 5b [2] 9a 50 [2] 81 1e [2] bc }

  condition:
    any of them
}