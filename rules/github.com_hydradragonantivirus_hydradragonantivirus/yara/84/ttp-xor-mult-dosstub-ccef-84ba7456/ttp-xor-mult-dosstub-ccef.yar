rule TTP_XOR_MULT_DOSStub_ccef {
  strings:
    $key_ccef = { 98 87 [2] ec 9f [2] ab 9d [2] ec 8c [2] a2 80 [2] ae 8a [2] b9 81 [2] a2 cf [2] 9f }

  condition:
    any of them
}