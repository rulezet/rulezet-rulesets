rule TTP_XOR_QUAD_CurrentVersionRun_12ce {
  strings:
    $key_12ce = { 41 a1 [2] 65 af [2] 4e 83 [2] 60 a1 [2] 74 ba [2] 7b a0 [2] 65 bd [2] 67 bc [2] 7c ba [2] 60 bd [2] 7c 92 }

  condition:
    any of them
}