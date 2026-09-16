rule TTP_XOR_MULT_DOSStub_cba2 {
  strings:
    $key_cba2 = { 9f ca [2] eb d2 [2] ac d0 [2] eb c1 [2] a5 cd [2] a9 c7 [2] be cc [2] a5 82 [2] 98 }

  condition:
    any of them
}