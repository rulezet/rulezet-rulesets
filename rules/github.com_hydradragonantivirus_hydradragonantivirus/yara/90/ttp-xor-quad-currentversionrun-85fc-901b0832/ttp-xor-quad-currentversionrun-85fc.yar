rule TTP_XOR_QUAD_CurrentVersionRun_85fc {
  strings:
    $key_85fc = { d6 93 [2] f2 9d [2] d9 b1 [2] f7 93 [2] e3 88 [2] ec 92 [2] f2 8f [2] f0 8e [2] eb 88 [2] f7 8f [2] eb a0 }

  condition:
    any of them
}