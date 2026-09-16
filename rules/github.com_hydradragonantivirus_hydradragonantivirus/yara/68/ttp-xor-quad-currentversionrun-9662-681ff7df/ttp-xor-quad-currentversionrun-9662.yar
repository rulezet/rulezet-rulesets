rule TTP_XOR_QUAD_CurrentVersionRun_9662 {
  strings:
    $key_9662 = { c5 0d [2] e1 03 [2] ca 2f [2] e4 0d [2] f0 16 [2] ff 0c [2] e1 11 [2] e3 10 [2] f8 16 [2] e4 11 [2] f8 3e }

  condition:
    any of them
}