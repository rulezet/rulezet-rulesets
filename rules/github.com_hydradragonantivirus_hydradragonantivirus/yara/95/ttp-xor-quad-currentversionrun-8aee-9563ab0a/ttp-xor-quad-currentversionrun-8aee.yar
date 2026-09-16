rule TTP_XOR_QUAD_CurrentVersionRun_8aee {
  strings:
    $key_8aee = { d9 81 [2] fd 8f [2] d6 a3 [2] f8 81 [2] ec 9a [2] e3 80 [2] fd 9d [2] ff 9c [2] e4 9a [2] f8 9d [2] e4 b2 }

  condition:
    any of them
}