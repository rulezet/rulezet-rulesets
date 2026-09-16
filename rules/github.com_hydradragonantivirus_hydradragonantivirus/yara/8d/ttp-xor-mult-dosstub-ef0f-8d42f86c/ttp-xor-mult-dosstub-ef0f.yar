rule TTP_XOR_MULT_DOSStub_ef0f {
  strings:
    $key_ef0f = { bb 67 [2] cf 7f [2] 88 7d [2] cf 6c [2] 81 60 [2] 8d 6a [2] 9a 61 [2] 81 2f [2] bc }

  condition:
    any of them
}