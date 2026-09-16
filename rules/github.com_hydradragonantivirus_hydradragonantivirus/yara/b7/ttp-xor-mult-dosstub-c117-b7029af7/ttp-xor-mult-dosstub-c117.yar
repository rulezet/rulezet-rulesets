rule TTP_XOR_MULT_DOSStub_c117 {
  strings:
    $key_c117 = { 95 7f [2] e1 67 [2] a6 65 [2] e1 74 [2] af 78 [2] a3 72 [2] b4 79 [2] af 37 [2] 92 }

  condition:
    any of them
}