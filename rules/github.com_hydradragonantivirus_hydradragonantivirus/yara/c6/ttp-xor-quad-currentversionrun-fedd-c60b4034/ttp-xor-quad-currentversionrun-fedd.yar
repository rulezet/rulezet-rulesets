rule TTP_XOR_QUAD_CurrentVersionRun_fedd {
  strings:
    $key_fedd = { ad b2 [2] 89 bc [2] a2 90 [2] 8c b2 [2] 98 a9 [2] 97 b3 [2] 89 ae [2] 8b af [2] 90 a9 [2] 8c ae [2] 90 81 }

  condition:
    any of them
}