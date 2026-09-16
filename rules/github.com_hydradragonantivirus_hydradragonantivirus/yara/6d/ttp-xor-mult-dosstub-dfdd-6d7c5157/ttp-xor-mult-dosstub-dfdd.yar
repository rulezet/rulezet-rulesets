rule TTP_XOR_MULT_DOSStub_dfdd {
  strings:
    $key_dfdd = { 8b b5 [2] ff ad [2] b8 af [2] ff be [2] b1 b2 [2] bd b8 [2] aa b3 [2] b1 fd [2] 8c }

  condition:
    any of them
}