rule TTP_XOR_QUAD_CurrentVersionRun_8da3 {
  strings:
    $key_8da3 = { de cc [2] fa c2 [2] d1 ee [2] ff cc [2] eb d7 [2] e4 cd [2] fa d0 [2] f8 d1 [2] e3 d7 [2] ff d0 [2] e3 ff }

  condition:
    any of them
}