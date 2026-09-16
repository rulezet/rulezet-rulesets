rule TTP_XOR_MULT_DOSStub_db6b {
  strings:
    $key_db6b = { 8f 03 [2] fb 1b [2] bc 19 [2] fb 08 [2] b5 04 [2] b9 0e [2] ae 05 [2] b5 4b [2] 88 }

  condition:
    any of them
}