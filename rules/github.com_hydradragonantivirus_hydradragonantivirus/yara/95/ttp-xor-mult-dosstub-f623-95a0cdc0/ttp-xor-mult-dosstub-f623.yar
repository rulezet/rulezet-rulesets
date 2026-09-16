rule TTP_XOR_MULT_DOSStub_f623 {
  strings:
    $key_f623 = { a2 4b [2] d6 53 [2] 91 51 [2] d6 40 [2] 98 4c [2] 94 46 [2] 83 4d [2] 98 03 [2] a5 }

  condition:
    any of them
}