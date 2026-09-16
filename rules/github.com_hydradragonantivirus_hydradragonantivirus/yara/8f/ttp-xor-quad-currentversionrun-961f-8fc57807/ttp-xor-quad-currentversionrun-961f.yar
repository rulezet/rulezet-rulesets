rule TTP_XOR_QUAD_CurrentVersionRun_961f {
  strings:
    $key_961f = { c5 70 [2] e1 7e [2] ca 52 [2] e4 70 [2] f0 6b [2] ff 71 [2] e1 6c [2] e3 6d [2] f8 6b [2] e4 6c [2] f8 43 }

  condition:
    any of them
}