rule TTP_XOR_MULT_DOSStub_b8a5 {
  strings:
    $key_b8a5 = { ec cd [2] 98 d5 [2] df d7 [2] 98 c6 [2] d6 ca [2] da c0 [2] cd cb [2] d6 85 [2] eb }

  condition:
    any of them
}