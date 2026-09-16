rule TTP_XOR_MULT_DOSStub_82a2 {
  strings:
    $key_82a2 = { d6 ca [2] a2 d2 [2] e5 d0 [2] a2 c1 [2] ec cd [2] e0 c7 [2] f7 cc [2] ec 82 [2] d1 }

  condition:
    any of them
}