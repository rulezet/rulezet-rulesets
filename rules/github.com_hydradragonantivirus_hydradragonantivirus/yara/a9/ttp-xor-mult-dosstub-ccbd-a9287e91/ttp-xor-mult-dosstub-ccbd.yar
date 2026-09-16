rule TTP_XOR_MULT_DOSStub_ccbd {
  strings:
    $key_ccbd = { 98 d5 [2] ec cd [2] ab cf [2] ec de [2] a2 d2 [2] ae d8 [2] b9 d3 [2] a2 9d [2] 9f }

  condition:
    any of them
}