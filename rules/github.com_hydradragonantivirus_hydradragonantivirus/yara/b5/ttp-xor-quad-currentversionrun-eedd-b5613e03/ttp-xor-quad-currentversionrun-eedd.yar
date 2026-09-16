rule TTP_XOR_QUAD_CurrentVersionRun_eedd {
  strings:
    $key_eedd = { bd b2 [2] 99 bc [2] b2 90 [2] 9c b2 [2] 88 a9 [2] 87 b3 [2] 99 ae [2] 9b af [2] 80 a9 [2] 9c ae [2] 80 81 }

  condition:
    any of them
}