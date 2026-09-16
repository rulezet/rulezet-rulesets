rule TTP_XOR_QUAD_CurrentVersionRun_8afa {
  strings:
    $key_8afa = { d9 95 [2] fd 9b [2] d6 b7 [2] f8 95 [2] ec 8e [2] e3 94 [2] fd 89 [2] ff 88 [2] e4 8e [2] f8 89 [2] e4 a6 }

  condition:
    any of them
}