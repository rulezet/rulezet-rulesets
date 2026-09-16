rule TTP_XOR_MULT_DOSStub_9961 {
  strings:
    $key_9961 = { cd 09 [2] b9 11 [2] fe 13 [2] b9 02 [2] f7 0e [2] fb 04 [2] ec 0f [2] f7 41 [2] ca }

  condition:
    any of them
}