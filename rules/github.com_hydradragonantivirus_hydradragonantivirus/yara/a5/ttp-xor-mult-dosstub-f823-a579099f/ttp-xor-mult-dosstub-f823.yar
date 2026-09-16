rule TTP_XOR_MULT_DOSStub_f823 {
  strings:
    $key_f823 = { ac 4b [2] d8 53 [2] 9f 51 [2] d8 40 [2] 96 4c [2] 9a 46 [2] 8d 4d [2] 96 03 [2] ab }

  condition:
    any of them
}