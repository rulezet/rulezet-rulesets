rule TTP_XOR_QUAD_CurrentVersionRun_a9c2 {
  strings:
    $key_a9c2 = { fa ad [2] de a3 [2] f5 8f [2] db ad [2] cf b6 [2] c0 ac [2] de b1 [2] dc b0 [2] c7 b6 [2] db b1 [2] c7 9e }

  condition:
    any of them
}