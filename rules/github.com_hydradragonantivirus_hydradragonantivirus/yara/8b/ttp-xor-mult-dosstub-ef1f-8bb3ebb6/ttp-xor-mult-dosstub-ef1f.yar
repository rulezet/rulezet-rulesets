rule TTP_XOR_MULT_DOSStub_ef1f {
  strings:
    $key_ef1f = { bb 77 [2] cf 6f [2] 88 6d [2] cf 7c [2] 81 70 [2] 8d 7a [2] 9a 71 [2] 81 3f [2] bc }

  condition:
    any of them
}