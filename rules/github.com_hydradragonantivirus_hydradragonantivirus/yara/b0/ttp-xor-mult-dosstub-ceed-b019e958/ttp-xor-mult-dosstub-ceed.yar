rule TTP_XOR_MULT_DOSStub_ceed {
  strings:
    $key_ceed = { 9a 85 [2] ee 9d [2] a9 9f [2] ee 8e [2] a0 82 [2] ac 88 [2] bb 83 [2] a0 cd [2] 9d }

  condition:
    any of them
}