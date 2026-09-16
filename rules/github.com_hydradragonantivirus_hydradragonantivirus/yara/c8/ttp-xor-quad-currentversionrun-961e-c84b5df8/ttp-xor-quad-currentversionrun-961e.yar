rule TTP_XOR_QUAD_CurrentVersionRun_961e {
  strings:
    $key_961e = { c5 71 [2] e1 7f [2] ca 53 [2] e4 71 [2] f0 6a [2] ff 70 [2] e1 6d [2] e3 6c [2] f8 6a [2] e4 6d [2] f8 42 }

  condition:
    any of them
}