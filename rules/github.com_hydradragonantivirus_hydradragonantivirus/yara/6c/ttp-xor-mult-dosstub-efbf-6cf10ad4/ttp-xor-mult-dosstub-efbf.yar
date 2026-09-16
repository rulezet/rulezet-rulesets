rule TTP_XOR_MULT_DOSStub_efbf {
  strings:
    $key_efbf = { bb d7 [2] cf cf [2] 88 cd [2] cf dc [2] 81 d0 [2] 8d da [2] 9a d1 [2] 81 9f [2] bc }

  condition:
    any of them
}