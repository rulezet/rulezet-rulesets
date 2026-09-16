rule TTP_XOR_MULT_DOSStub_deed {
  strings:
    $key_deed = { 8a 85 [2] fe 9d [2] b9 9f [2] fe 8e [2] b0 82 [2] bc 88 [2] ab 83 [2] b0 cd [2] 8d }

  condition:
    any of them
}