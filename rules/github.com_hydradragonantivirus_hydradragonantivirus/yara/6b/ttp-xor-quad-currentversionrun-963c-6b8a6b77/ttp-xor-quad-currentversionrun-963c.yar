rule TTP_XOR_QUAD_CurrentVersionRun_963c {
  strings:
    $key_963c = { c5 53 [2] e1 5d [2] ca 71 [2] e4 53 [2] f0 48 [2] ff 52 [2] e1 4f [2] e3 4e [2] f8 48 [2] e4 4f [2] f8 60 }

  condition:
    any of them
}