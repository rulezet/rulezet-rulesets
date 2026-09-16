rule TTP_XOR_QUAD_CurrentVersionRun_8a1f {
  strings:
    $key_8a1f = { d9 70 [2] fd 7e [2] d6 52 [2] f8 70 [2] ec 6b [2] e3 71 [2] fd 6c [2] ff 6d [2] e4 6b [2] f8 6c [2] e4 43 }

  condition:
    any of them
}