rule TTP_XOR_QUAD_CurrentVersionRun_822f {
  strings:
    $key_822f = { d1 40 [2] f5 4e [2] de 62 [2] f0 40 [2] e4 5b [2] eb 41 [2] f5 5c [2] f7 5d [2] ec 5b [2] f0 5c [2] ec 73 }

  condition:
    any of them
}