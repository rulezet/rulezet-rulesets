rule TTP_XOR_MULT_DOSStub_bfcd {
  strings:
    $key_bfcd = { eb a5 [2] 9f bd [2] d8 bf [2] 9f ae [2] d1 a2 [2] dd a8 [2] ca a3 [2] d1 ed [2] ec }

  condition:
    any of them
}