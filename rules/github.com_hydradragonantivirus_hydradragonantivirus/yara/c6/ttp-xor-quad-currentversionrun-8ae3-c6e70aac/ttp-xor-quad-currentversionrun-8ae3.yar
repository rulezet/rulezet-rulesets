rule TTP_XOR_QUAD_CurrentVersionRun_8ae3 {
  strings:
    $key_8ae3 = { d9 8c [2] fd 82 [2] d6 ae [2] f8 8c [2] ec 97 [2] e3 8d [2] fd 90 [2] ff 91 [2] e4 97 [2] f8 90 [2] e4 bf }

  condition:
    any of them
}