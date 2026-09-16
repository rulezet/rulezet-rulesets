rule TTP_XOR_QUAD_CurrentVersionRun_24bf {
  strings:
    $key_24bf = { 77 d0 [2] 53 de [2] 78 f2 [2] 56 d0 [2] 42 cb [2] 4d d1 [2] 53 cc [2] 51 cd [2] 4a cb [2] 56 cc [2] 4a e3 }

  condition:
    any of them
}