rule TTP_XOR_QUAD_CurrentVersionRun_99cb {
  strings:
    $key_99cb = { ca a4 [2] ee aa [2] c5 86 [2] eb a4 [2] ff bf [2] f0 a5 [2] ee b8 [2] ec b9 [2] f7 bf [2] eb b8 [2] f7 97 }

  condition:
    any of them
}