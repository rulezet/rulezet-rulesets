rule TTP_XOR_MULT_DOSStub_dff3 {
  strings:
    $key_dff3 = { 8b 9b [2] ff 83 [2] b8 81 [2] ff 90 [2] b1 9c [2] bd 96 [2] aa 9d [2] b1 d3 [2] 8c }

  condition:
    any of them
}