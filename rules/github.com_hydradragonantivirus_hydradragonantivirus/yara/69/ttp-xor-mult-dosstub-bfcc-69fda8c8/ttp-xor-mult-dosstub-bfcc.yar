rule TTP_XOR_MULT_DOSStub_bfcc {
  strings:
    $key_bfcc = { eb a4 [2] 9f bc [2] d8 be [2] 9f af [2] d1 a3 [2] dd a9 [2] ca a2 [2] d1 ec [2] ec }

  condition:
    any of them
}