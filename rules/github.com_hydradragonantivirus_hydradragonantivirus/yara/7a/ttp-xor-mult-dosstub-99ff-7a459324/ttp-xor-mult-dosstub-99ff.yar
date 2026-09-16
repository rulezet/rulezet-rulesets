rule TTP_XOR_MULT_DOSStub_99ff {
  strings:
    $key_99ff = { cd 97 [2] b9 8f [2] fe 8d [2] b9 9c [2] f7 90 [2] fb 9a [2] ec 91 [2] f7 df [2] ca }

  condition:
    any of them
}