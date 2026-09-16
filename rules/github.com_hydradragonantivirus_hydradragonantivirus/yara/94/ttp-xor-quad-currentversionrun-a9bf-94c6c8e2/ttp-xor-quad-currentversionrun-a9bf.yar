rule TTP_XOR_QUAD_CurrentVersionRun_a9bf {
  strings:
    $key_a9bf = { fa d0 [2] de de [2] f5 f2 [2] db d0 [2] cf cb [2] c0 d1 [2] de cc [2] dc cd [2] c7 cb [2] db cc [2] c7 e3 }

  condition:
    any of them
}