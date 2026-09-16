rule TTP_XOR_QUAD_CurrentVersionRun_94e3 {
  strings:
    $key_94e3 = { c7 8c [2] e3 82 [2] c8 ae [2] e6 8c [2] f2 97 [2] fd 8d [2] e3 90 [2] e1 91 [2] fa 97 [2] e6 90 [2] fa bf }

  condition:
    any of them
}