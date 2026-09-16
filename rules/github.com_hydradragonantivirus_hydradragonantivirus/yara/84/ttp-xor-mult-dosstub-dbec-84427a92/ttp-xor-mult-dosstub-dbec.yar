rule TTP_XOR_MULT_DOSStub_dbec {
  strings:
    $key_dbec = { 8f 84 [2] fb 9c [2] bc 9e [2] fb 8f [2] b5 83 [2] b9 89 [2] ae 82 [2] b5 cc [2] 88 }

  condition:
    any of them
}