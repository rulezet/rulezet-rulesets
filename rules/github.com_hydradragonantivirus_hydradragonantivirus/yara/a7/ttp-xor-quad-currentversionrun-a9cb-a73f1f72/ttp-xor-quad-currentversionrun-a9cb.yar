rule TTP_XOR_QUAD_CurrentVersionRun_a9cb {
  strings:
    $key_a9cb = { fa a4 [2] de aa [2] f5 86 [2] db a4 [2] cf bf [2] c0 a5 [2] de b8 [2] dc b9 [2] c7 bf [2] db b8 [2] c7 97 }

  condition:
    any of them
}