rule TTP_XOR_MULT_DOSStub_c9dc {
  strings:
    $key_c9dc = { 9d b4 [2] e9 ac [2] ae ae [2] e9 bf [2] a7 b3 [2] ab b9 [2] bc b2 [2] a7 fc [2] 9a }

  condition:
    any of them
}