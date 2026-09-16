rule TTP_XOR_MULT_DOSStub_9967 {
  strings:
    $key_9967 = { cd 0f [2] b9 17 [2] fe 15 [2] b9 04 [2] f7 08 [2] fb 02 [2] ec 09 [2] f7 47 [2] ca }

  condition:
    any of them
}