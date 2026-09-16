rule TTP_XOR_QUAD_CurrentVersionRun_aca3 {
  strings:
    $key_aca3 = { ff cc [2] db c2 [2] f0 ee [2] de cc [2] ca d7 [2] c5 cd [2] db d0 [2] d9 d1 [2] c2 d7 [2] de d0 [2] c2 ff }

  condition:
    any of them
}