rule TTP_XOR_MULT_DOSStub_debf {
  strings:
    $key_debf = { 8a d7 [2] fe cf [2] b9 cd [2] fe dc [2] b0 d0 [2] bc da [2] ab d1 [2] b0 9f [2] 8d }

  condition:
    any of them
}