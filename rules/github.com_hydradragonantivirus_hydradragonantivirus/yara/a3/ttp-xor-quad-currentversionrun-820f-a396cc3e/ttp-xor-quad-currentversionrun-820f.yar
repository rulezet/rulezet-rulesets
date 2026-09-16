rule TTP_XOR_QUAD_CurrentVersionRun_820f {
  strings:
    $key_820f = { d1 60 [2] f5 6e [2] de 42 [2] f0 60 [2] e4 7b [2] eb 61 [2] f5 7c [2] f7 7d [2] ec 7b [2] f0 7c [2] ec 53 }

  condition:
    any of them
}