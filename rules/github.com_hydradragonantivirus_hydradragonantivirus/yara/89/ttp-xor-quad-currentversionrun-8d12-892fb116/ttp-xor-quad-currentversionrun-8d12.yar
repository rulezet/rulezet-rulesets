rule TTP_XOR_QUAD_CurrentVersionRun_8d12 {
  strings:
    $key_8d12 = { de 7d [2] fa 73 [2] d1 5f [2] ff 7d [2] eb 66 [2] e4 7c [2] fa 61 [2] f8 60 [2] e3 66 [2] ff 61 [2] e3 4e }

  condition:
    any of them
}